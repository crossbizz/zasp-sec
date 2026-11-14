package hostedgateway

import (
	"encoding/json"
	"strings"
)

// Streamed answers of the three APIs.
//
// DOCUMENTED: https://github.com/openai/openai-openapi (openapi.yaml, branch
// manual_spec). A chat completion stream is "data:" lines, each a
// chat.completion.chunk with choices[].index, choices[].delta.content,
// choices[].delta.tool_calls[].index and .function.arguments, and
// choices[].finish_reason, ended by "data: [DONE]". A Responses stream is
// typed events; the proxy rewrites response.output_text.delta (delta),
// response.output_text.done (text), response.content_part.done (part.text),
// response.output_item.done (item) and response.completed (response.output),
// each located by output_index and content_index. Its error event is
// {"type":"error","code","message","param"}.
// UNVERIFIED: response.function_call_arguments.delta (delta) and .done
// (arguments) are in that specification for the Realtime API; that the
// Responses stream uses the same two names and members is from memory.
// An {"error":{...}} object as a data line of a chat completion stream is
// raised as an error by the openai Python SDK (3.51.0), and the Messages
// error event by the anthropic Python SDK (2.8.0): both are run in
// TestRealModelSDKsThroughTheProxy.
//
// DOCUMENTED: https://platform.claude.com/docs/en/build-with-claude/streaming.
// A Messages stream is named events: content_block_delta with index and a
// delta of type text_delta (text) or input_json_delta (partial_json),
// content_block_stop with index, message_stop, and
// "event: error" with {"type":"error","error":{"type","message"}}. Thinking
// deltas are passed unchanged: a thinking block is signed, and changing its
// text would make the block unusable in the next request.
//
// What is held back by the window is released before the event that ends its
// text: an extra delta event of the same shape, placed before the provider's
// finish_reason chunk, content_block_stop or *.done event.

type heldText struct {
	stream *TextStream
	// released is everything the stream released so far (the Responses API
	// repeats the whole text in its final events).
	released strings.Builder
	// make builds the extra delta event that carries text released at the
	// end.
	make func(text string) sseEvent
	keep bool
}

type llmStream struct {
	api        string
	inspection *Inspection
	held       map[string]*heldText
	order      []string
	// template holds the members of the newest chat completion chunk that
	// identify the completion, for the extra chunks.
	template map[string]any
}

func newLLMStream(api string, inspection *Inspection) *llmStream {
	return &llmStream{api: api, inspection: inspection, held: map[string]*heldText{}}
}

func (state *llmStream) text(key string, make func(string) sseEvent) *heldText {
	if existing, has := state.held[key]; has {
		return existing
	}
	created := &heldText{stream: state.inspection.Stream(), make: make, keep: state.api == APIResponses}
	state.held[key] = created
	state.order = append(state.order, key)
	return created
}

func (held *heldText) push(piece string) (string, bool) {
	out, ok := held.stream.Push(piece)
	if held.keep {
		held.released.WriteString(out)
	}
	return out, ok
}

// flush ends the texts whose key has the prefix and returns the extra events
// that carry what was still held.
func (state *llmStream) flush(prefix string) ([]sseEvent, bool) {
	var events []sseEvent
	remaining := state.order[:0]
	for _, key := range state.order {
		if !strings.HasPrefix(key, prefix) {
			remaining = append(remaining, key)
			continue
		}
		held := state.held[key]
		rest, ok := held.stream.Flush()
		if !ok {
			return nil, false
		}
		if held.keep {
			held.released.WriteString(rest)
		}
		if rest != "" {
			events = append(events, held.make(rest))
		}
		if state.api != APIResponses {
			delete(state.held, key)
		}
	}
	state.order = remaining
	return events, true
}

func (state *llmStream) flushAll() ([]sseEvent, bool) { return state.flush("") }

// refusal is the event that ends a stream the gateway cuts.
func (state *llmStream) refusal() sseEvent {
	message := refusalText(state.inspection.Verdict().Reason)
	switch state.api {
	case APIMessages:
		return sseEvent{Name: "error", HasData: true, Data: string(encodeJSON(map[string]any{"type": "error", "error": map[string]any{"type": "invalid_request_error", "message": message}}))}
	case APIResponses:
		return sseEvent{Name: "error", HasData: true, Data: string(encodeJSON(map[string]any{"type": "error", "code": "guardrail_blocked", "message": message, "param": nil}))}
	}
	return sseEvent{HasData: true, Data: string(llmErrorBody(APIChatCompletions, 400, "guardrail_blocked", message))}
}

func dataEvent(name string, value any) sseEvent {
	return sseEvent{Name: name, HasData: true, Data: string(encodeJSON(value))}
}

func indexKey(value any) string {
	switch typed := value.(type) {
	case json.Number:
		return typed.String()
	case string:
		return typed
	}
	return "0"
}

// event takes one event of the provider and returns the events to send in
// its place. The second result is false when the stream must end.
func (state *llmStream) event(event sseEvent) ([]sseEvent, bool) {
	if !event.HasData {
		return []sseEvent{event}, true
	}
	if strings.TrimSpace(event.Data) == "[DONE]" {
		extra, ok := state.flushAll()
		return append(extra, event), ok
	}
	value, parsed := decodeAny([]byte(event.Data))
	object, isObject := value.(map[string]any)
	if !parsed || !isObject {
		return []sseEvent{event}, true
	}
	var extra []sseEvent
	ok := true
	switch state.api {
	case APIChatCompletions:
		extra, ok = state.chatChunk(object)
	case APIMessages:
		extra, ok = state.messagesEvent(object)
	case APIResponses:
		extra, ok = state.responsesEvent(object)
	}
	if !ok {
		return nil, false
	}
	event.Data = string(encodeJSON(object))
	return append(extra, event), true
}

func (state *llmStream) chatChunk(chunk map[string]any) ([]sseEvent, bool) {
	choices, isList := chunk["choices"].([]any)
	if !isList {
		return nil, true
	}
	template := map[string]any{}
	for _, member := range []string{"id", "object", "created", "model", "system_fingerprint", "service_tier"} {
		if value, has := chunk[member]; has {
			template[member] = value
		}
	}
	state.template = template
	extraChunk := func(index any, delta map[string]any) sseEvent {
		chunk := map[string]any{"choices": []any{map[string]any{"index": index, "delta": delta, "finish_reason": nil}}}
		for member, value := range state.template {
			chunk[member] = value
		}
		return dataEvent("", chunk)
	}
	var extra []sseEvent
	for _, entry := range choices {
		choice, isObject := entry.(map[string]any)
		if !isObject {
			continue
		}
		index := choice["index"]
		prefix := "c" + indexKey(index) + ":"
		if delta, hasDelta := choice["delta"].(map[string]any); hasDelta {
			if content, isString := delta["content"].(string); isString {
				held := state.text(prefix+"content", func(text string) sseEvent { return extraChunk(index, map[string]any{"content": text}) })
				out, ok := held.push(content)
				if !ok {
					return nil, false
				}
				delta["content"] = out
			}
			calls, _ := delta["tool_calls"].([]any)
			for _, item := range calls {
				call, _ := item.(map[string]any)
				function, _ := call["function"].(map[string]any)
				arguments, isString := function["arguments"].(string)
				if !isString {
					continue
				}
				callIndex := call["index"]
				held := state.text(prefix+"tool:"+indexKey(callIndex), func(text string) sseEvent {
					return extraChunk(index, map[string]any{"tool_calls": []any{map[string]any{"index": callIndex, "function": map[string]any{"arguments": text}}}})
				})
				out, ok := held.push(arguments)
				if !ok {
					return nil, false
				}
				function["arguments"] = out
			}
		}
		if choice["finish_reason"] != nil {
			flushed, ok := state.flush(prefix)
			if !ok {
				return nil, false
			}
			extra = append(extra, flushed...)
		}
	}
	return extra, true
}

func (state *llmStream) messagesEvent(event map[string]any) ([]sseEvent, bool) {
	switch event["type"] {
	case "content_block_delta":
		delta, _ := event["delta"].(map[string]any)
		index := event["index"]
		member := ""
		switch delta["type"] {
		case "text_delta":
			member = "text"
		case "input_json_delta":
			member = "partial_json"
		}
		piece, isString := delta[member].(string)
		if member == "" || !isString {
			return nil, true
		}
		kind := delta["type"]
		held := state.text("b"+indexKey(index)+":", func(text string) sseEvent {
			return dataEvent("content_block_delta", map[string]any{"type": "content_block_delta", "index": index, "delta": map[string]any{"type": kind, member: text}})
		})
		out, ok := held.push(piece)
		if !ok {
			return nil, false
		}
		delta[member] = out
	case "content_block_stop":
		return state.flush("b" + indexKey(event["index"]) + ":")
	case "message_stop":
		return state.flushAll()
	}
	return nil, true
}

func (state *llmStream) responsesEvent(event map[string]any) ([]sseEvent, bool) {
	kind, _ := event["type"].(string)
	output := indexKey(event["output_index"])
	// located copies the members that say where a delta belongs.
	located := func(deltaType, text string) sseEvent {
		extra := map[string]any{"type": deltaType, "delta": text}
		for _, member := range []string{"item_id", "output_index", "content_index", "sequence_number"} {
			if value, has := event[member]; has {
				extra[member] = value
			}
		}
		return dataEvent(deltaType, extra)
	}
	switch kind {
	case "response.output_text.delta", "response.function_call_arguments.delta":
		piece, isString := event["delta"].(string)
		if !isString {
			return nil, true
		}
		key := "o" + output + "." + indexKey(event["content_index"])
		if kind == "response.function_call_arguments.delta" {
			key = "a" + output
		}
		deltaType := kind
		out, ok := state.text(key, func(text string) sseEvent { return located(deltaType, text) }).push(piece)
		if !ok {
			return nil, false
		}
		event["delta"] = out
	case "response.output_text.done", "response.function_call_arguments.done":
		key, member, deltaType := "o"+output+"."+indexKey(event["content_index"]), "text", "response.output_text.delta"
		if kind == "response.function_call_arguments.done" {
			key, member, deltaType = "a"+output, "arguments", "response.function_call_arguments.delta"
		}
		held, known := state.held[key]
		if !known {
			if value, isString := event[member].(string); isString {
				out, ok := state.inspection.Text(value)
				if !ok {
					return nil, false
				}
				event[member] = out
			}
			return nil, true
		}
		rest, ok := held.stream.Flush()
		if !ok {
			return nil, false
		}
		held.released.WriteString(rest)
		if _, isString := event[member].(string); isString {
			event[member] = held.released.String()
		}
		if rest != "" {
			return []sseEvent{located(deltaType, rest)}, true
		}
	case "response.content_part.done":
		if part, isObject := event["part"].(map[string]any); isObject {
			if value, isString := part["text"].(string); isString {
				if held, known := state.held["o"+output+"."+indexKey(event["content_index"])]; known {
					part["text"] = held.released.String()
				} else if out, ok := state.inspection.Text(value); ok {
					part["text"] = out
				}
			}
		}
	case "response.output_item.done":
		if item, isObject := event["item"].(map[string]any); isObject {
			inspectResponsesItem(item, output, state.inspection, state.releasedTexts())
		}
	case "response.completed", "response.incomplete", "response.failed":
		response, _ := event["response"].(map[string]any)
		items, _ := response["output"].([]any)
		for index, entry := range items {
			if item, isObject := entry.(map[string]any); isObject {
				inspectResponsesItem(item, itoa(index), state.inspection, state.releasedTexts())
			}
		}
	}
	return nil, !state.inspection.Blocked()
}

func (state *llmStream) releasedTexts() map[string]*strings.Builder {
	released := make(map[string]*strings.Builder, len(state.held))
	for key, held := range state.held {
		released[key] = &held.released
	}
	return released
}
