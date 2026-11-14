// Package hostedgateway is the engine of the gateway the platform hosts: an
// MCP gateway in front of a customer's remote MCP servers and a guardrail
// proxy in front of model providers. Nothing is installed at the customer:
// an agent's configuration names the platform's URL instead of the server's
// or the provider's, and presents a platform token.
//
// The package holds no database and no credential. A request is given a
// Store that answers what the Environment's policy is and takes the decision
// records; the text of a prompt, an argument, a tool result or an answer
// exists only in the process for the duration of the request and is never
// logged or recorded.
package hostedgateway

import (
	"crypto/sha256"
	"encoding/hex"
	"hash"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/zasp-ai/zasp-sec/services/platform/guardrail"
)

// Modes is an Environment's guardrail policy: the mode of each rule it
// names. A rule it does not name, or names with a mode the rule cannot take,
// has its default.
type Modes map[string]guardrail.Mode

func (modes Modes) of(rule guardrail.Rule) guardrail.Mode {
	if mode, ok := modes[rule.ID]; ok && guardrail.ValidMode(rule, mode) {
		return mode
	}
	return rule.DefaultMode
}

// Reasons a decision names besides the guardrail rules.
const (
	ReasonNone             = "none"
	ReasonGuardrail        = "guardrail"
	ReasonServerBlocked    = "server_blocked"
	ReasonServerUnapproved = "server_unapproved"
	ReasonServerDisabled   = "server_disabled"
	ReasonToolDenied       = "tool_denied"
	ReasonToolNotAllowed   = "tool_not_allowed"
	ReasonToolRiskDenied   = "tool_risk_denied"
	ReasonWindowExceeded   = "stream_window_exceeded"
)

// MatchedRule is one rule that matched, with the mode it was applied in.
type MatchedRule struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Mode     string `json:"mode"`
	Count    int    `json:"count"`
}

// Verdict is the outcome of inspecting one direction of one exchange.
type Verdict struct {
	Decision string
	Reason   string
	Rules    []MatchedRule
	Bytes    int64
	Digest   string
}

// Inspection applies the guardrail detectors to the texts of one direction
// of one exchange (the request or the response) and accumulates the outcome.
// It keeps counts, a size and a digest; it keeps no text.
type Inspection struct {
	modes     Modes
	direction guardrail.Direction
	counts    map[string]int
	bytes     int64
	digest    hash.Hash
	blocked   bool
	redacted  bool
	overflow  bool
}

// NewInspection starts an inspection under the Environment's modes.
func NewInspection(modes Modes, direction guardrail.Direction) *Inspection {
	return &Inspection{modes: modes, direction: direction, counts: map[string]int{}, digest: sha256.New()}
}

// Observe adds raw bytes of the exchange (the HTTP body as it was received)
// to the size and the digest of the record.
func (inspection *Inspection) Observe(raw []byte) {
	inspection.bytes += int64(len(raw))
	_, _ = inspection.digest.Write(raw)
}

// Blocked reports whether a rule in block mode matched, or a stream had to be
// cut because a match could not be held within the window.
func (inspection *Inspection) Blocked() bool { return inspection.blocked }

// Redacted reports whether any text was changed.
func (inspection *Inspection) Redacted() bool { return inspection.redacted }

// Block records a refusal the detectors did not make (a text that cannot be
// inspected safely).
func (inspection *Inspection) Block() { inspection.blocked = true }

func (inspection *Inspection) modeMap(trusted bool) map[string]guardrail.Mode {
	modes := make(map[string]guardrail.Mode, len(guardrail.Rules()))
	for _, rule := range guardrail.Rules() {
		mode := inspection.modes.of(rule)
		// A trusted text is one the operator of the agent wrote (a system
		// prompt): it is not searched for injected instructions, only for
		// sensitive data.
		if trusted && rule.Category == guardrail.CategoryPromptInjection {
			mode = guardrail.ModeOff
		}
		modes[rule.ID] = mode
	}
	return modes
}

// Text inspects one complete text and returns what may be forwarded in its
// place: the text itself, or the text with the matches of redacting rules
// replaced. The second result is false when the text must not be forwarded.
func (inspection *Inspection) Text(text string) (string, bool) { return inspection.text(text, false) }

// TrustedText inspects a text the operator of the agent wrote, such as a
// system prompt, for sensitive data only.
func (inspection *Inspection) TrustedText(text string) (string, bool) {
	return inspection.text(text, true)
}

func (inspection *Inspection) text(text string, trusted bool) (string, bool) {
	if inspection.blocked {
		return "", false
	}
	if text == "" {
		return "", true
	}
	if !utf8.ValidString(text) {
		text = strings.ToValidUTF8(text, "\uFFFD")
	}
	if len(text) > guardrail.MaxTextBytes {
		// A text longer than one detection takes is inspected through the
		// same window a stream is.
		stream := &TextStream{inspection: inspection, trusted: trusted}
		head, ok := stream.Push(text)
		if !ok {
			return "", false
		}
		tail, ok := stream.Flush()
		if !ok {
			return "", false
		}
		return head + tail, true
	}
	matches, ok := guardrail.Detect(text, inspection.direction)
	if !ok {
		inspection.blocked = true
		return "", false
	}
	decision := guardrail.Decide(text, matches, inspection.modeMap(trusted))
	for _, rule := range decision.Rules {
		inspection.counts[rule.ID] += rule.Count
	}
	switch decision.Decision {
	case guardrail.DecisionBlock:
		inspection.blocked = true
		return "", false
	case guardrail.DecisionRedact:
		inspection.redacted = true
		return decision.RedactedText, true
	}
	return text, true
}

// Stream returns an inspector of a text that arrives in pieces.
func (inspection *Inspection) Stream() *TextStream { return &TextStream{inspection: inspection} }

// Verdict is the outcome so far.
func (inspection *Inspection) Verdict() Verdict {
	verdict := Verdict{Decision: guardrail.DecisionAllow, Reason: ReasonNone, Rules: []MatchedRule{}, Bytes: inspection.bytes, Digest: "sha256:" + hex.EncodeToString(inspection.digest.Sum(nil))}
	modes := inspection.modeMap(false)
	for _, rule := range guardrail.Rules() {
		count := inspection.counts[rule.ID]
		if count == 0 {
			continue
		}
		if count > 9999 {
			count = 9999
		}
		verdict.Rules = append(verdict.Rules, MatchedRule{ID: rule.ID, Category: rule.Category, Mode: string(modes[rule.ID]), Count: count})
	}
	switch {
	case inspection.blocked:
		verdict.Decision, verdict.Reason = guardrail.DecisionBlock, ReasonGuardrail
		if inspection.overflow {
			verdict.Reason = ReasonWindowExceeded
		}
	case inspection.redacted:
		verdict.Decision, verdict.Reason = guardrail.DecisionRedact, ReasonGuardrail
	}
	return verdict
}

// The window of a stream.
//
// A text that arrives in pieces cannot be searched piece by piece: an email
// address, a card number or an injected instruction can lie across two
// pieces. A TextStream therefore keeps the newest StreamWindowBytes of the
// text back. It searches everything it holds, releases only what lies before
// the window, and never releases part of a match:
//
//   - a match that ends inside the window is held from its start, because the
//     next piece may extend it;
//   - a run of token characters (letters, digits and ._~+/=-) is never cut,
//     up to streamTokenBytes, so a long token (a JSON Web Token, a bearer
//     token) is seen whole, together with a "Bearer " before it;
//   - a private key block is held from its BEGIN line until its END line.
//
// Every match of at most StreamWindowBytes is therefore found exactly as it
// would be in the complete text. What is released keeps a short tail as
// context for the next search (a detector looks a few bytes back to tell a
// number inside a longer identifier, or a negation before a verb).
//
// When what must be held grows past the size one detection takes, the stream
// is refused rather than released unsearched.
const (
	StreamWindowBytes  = 256
	streamContextBytes = 64
	streamPieceBytes   = 4096
	streamTokenBytes   = 8192
	streamHoldBytes    = guardrail.MaxTextBytes - streamContextBytes - streamPieceBytes
)

var bearerBeforePattern = regexp.MustCompile(`(?i)bearer\s+$`)

func tokenByte(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value == '.' || value == '_' || value == '~' || value == '+' || value == '/' || value == '=' || value == '-'
}

// TextStream inspects one text that arrives in pieces: the content of one
// choice of a streamed completion, the arguments of one streamed tool call.
type TextStream struct {
	inspection *Inspection
	trusted    bool
	// context is the tail of what was released, kept for the detectors'
	// look-behind; pending is what is held.
	context string
	pending string
	carry   string
	failed  bool
}

// Push adds a piece and returns what may be forwarded now. The second result
// is false when the stream must end: nothing more of it may be forwarded.
func (stream *TextStream) Push(piece string) (string, bool) {
	if stream.failed || stream.inspection.blocked {
		stream.failed = true
		return "", false
	}
	// A character cut in two by the sender is completed by the next piece.
	piece = stream.carry + piece
	stream.carry = ""
	for cut := 1; cut <= 3 && cut <= len(piece); cut++ {
		if tail := piece[len(piece)-cut:]; utf8.RuneStart(tail[0]) {
			if !utf8.FullRuneInString(tail) {
				stream.carry, piece = tail, piece[:len(piece)-cut]
			}
			break
		}
	}
	if !utf8.ValidString(piece) {
		piece = strings.ToValidUTF8(piece, "\uFFFD")
	}
	var released strings.Builder
	for len(piece) > 0 {
		size := len(piece)
		if size > streamPieceBytes {
			size = streamPieceBytes
			for size > 0 && !utf8.RuneStart(piece[size]) {
				size--
			}
		}
		stream.pending += piece[:size]
		piece = piece[size:]
		out, ok := stream.release(false)
		if !ok {
			stream.failed = true
			return "", false
		}
		released.WriteString(out)
	}
	return released.String(), true
}

// Flush ends the text and returns the rest of it.
func (stream *TextStream) Flush() (string, bool) {
	if stream.failed || stream.inspection.blocked {
		stream.failed = true
		return "", false
	}
	if stream.carry != "" {
		stream.pending += "\uFFFD"
		stream.carry = ""
	}
	out, ok := stream.release(true)
	if !ok {
		stream.failed = true
		return "", false
	}
	return out, true
}

func (stream *TextStream) release(final bool) (string, bool) {
	inspection := stream.inspection
	text := stream.context + stream.pending
	base := len(stream.context)
	if len(stream.pending) == 0 {
		return "", true
	}
	matches, ok := guardrail.Detect(text, inspection.direction)
	if !ok {
		inspection.blocked, inspection.overflow = true, true
		return "", false
	}
	modes := inspection.modeMap(stream.trusted)
	live := matches[:0]
	for _, match := range matches {
		if match.End <= base || modes[match.RuleID] == guardrail.ModeOff {
			continue
		}
		if modes[match.RuleID] == guardrail.ModeBlock {
			inspection.counts[match.RuleID]++
			inspection.blocked = true
			return "", false
		}
		if match.Start < base {
			// The match began in text that was already released (it is
			// longer than the window): what is still held of it is redacted.
			match.Start = base
		}
		live = append(live, match)
	}
	limit := len(text)
	if !final {
		limit -= StreamWindowBytes
		if limit < base {
			limit = base
		}
		for changed := true; changed; {
			changed = false
			for _, match := range live {
				open := match.End > limit || match.RuleID == guardrail.RulePrivateKey && !strings.Contains(text[match.Start:match.End], "-----END")
				if open && match.Start < limit {
					limit, changed = match.Start, true
				}
			}
			// A token is not cut, nor is the "Bearer " before it.
			if limit > base && limit < len(text) && tokenByte(text[limit]) && tokenByte(text[limit-1]) {
				start := limit
				for start > base && limit-start < streamTokenBytes && tokenByte(text[start-1]) {
					start--
				}
				if limit-start < streamTokenBytes {
					limit, changed = start, true
				}
			}
			if limit > base {
				from := limit - 16
				if from < base {
					from = base
				}
				if location := bearerBeforePattern.FindStringIndex(text[from:limit]); location != nil && limit < len(text) && tokenByte(text[limit]) {
					limit, changed = from+location[0], true
				}
			}
			for limit > base && limit < len(text) && !utf8.RuneStart(text[limit]) {
				limit--
				changed = true
			}
		}
	}
	var out strings.Builder
	position := base
	for _, match := range live {
		if match.End > limit {
			continue
		}
		inspection.counts[match.RuleID]++
		if modes[match.RuleID] != guardrail.ModeRedact || match.End <= position {
			continue
		}
		if match.Start >= position {
			out.WriteString(text[position:match.Start])
			out.WriteString("[REDACTED:" + match.RuleID + "]")
			inspection.redacted = true
		}
		position = match.End
	}
	if position < limit {
		out.WriteString(text[position:limit])
	}
	tail := limit - streamContextBytes
	if tail < 0 {
		tail = 0
	}
	for tail < limit && !utf8.RuneStart(text[tail]) {
		tail++
	}
	stream.context, stream.pending = text[tail:limit], text[limit:]
	if !final && len(stream.pending) > streamHoldBytes {
		inspection.blocked, inspection.overflow = true, true
		return "", false
	}
	return out.String(), true
}
