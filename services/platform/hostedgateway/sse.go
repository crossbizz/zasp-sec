package hostedgateway

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net/http"
	"strings"
)

// Server-sent events, as both MCP's Streamable HTTP transport and the model
// providers' streaming responses use them: events separated by a blank line,
// each made of "field: value" lines; the data of an event is its data lines
// joined by a newline; a line that starts with a colon is a comment.

var errEventTooLarge = errors.New("server-sent event too large")

type sseEvent struct {
	Name    string
	Data    string
	ID      string
	Retry   string
	HasData bool
	HasID   bool
	// Comments are the comment lines of the event, without the colon.
	Comments []string
}

type sseReader struct {
	reader  *bufio.Reader
	maximum int
	// read counts the bytes taken from the upstream; observe, when set, is
	// given every line as it was received.
	observe func([]byte)
}

func newSSEReader(source io.Reader, maximum int, observe func([]byte)) *sseReader {
	return &sseReader{reader: bufio.NewReaderSize(source, 32*1024), maximum: maximum, observe: observe}
}

// Next returns the next event. It returns io.EOF at the end of the stream; an
// event the stream ended in the middle of is dropped, as the specification of
// server-sent events says.
func (reader *sseReader) Next() (sseEvent, error) {
	var event sseEvent
	var data []string
	size := 0
	seen := false
	for {
		line, err := reader.reader.ReadSlice('\n')
		for errors.Is(err, bufio.ErrBufferFull) {
			// A line longer than the buffer: collect it, within the bound.
			collected := append([]byte(nil), line...)
			for errors.Is(err, bufio.ErrBufferFull) {
				if len(collected) > reader.maximum {
					return sseEvent{}, errEventTooLarge
				}
				line, err = reader.reader.ReadSlice('\n')
				collected = append(collected, line...)
			}
			line = collected
		}
		if len(line) > 0 && reader.observe != nil {
			reader.observe(line)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return sseEvent{}, io.EOF
			}
			return sseEvent{}, err
		}
		size += len(line)
		if size > reader.maximum {
			return sseEvent{}, errEventTooLarge
		}
		line = bytes.TrimRight(line, "\r\n")
		if len(line) == 0 {
			if !seen {
				continue
			}
			event.Data = strings.Join(data, "\n")
			return event, nil
		}
		seen = true
		if line[0] == ':' {
			event.Comments = append(event.Comments, string(line[1:]))
			continue
		}
		field, value := string(line), ""
		if index := bytes.IndexByte(line, ':'); index >= 0 {
			field, value = string(line[:index]), strings.TrimPrefix(string(line[index+1:]), " ")
		}
		switch field {
		case "event":
			event.Name = value
		case "data":
			data = append(data, value)
			event.HasData = true
		case "id":
			event.ID, event.HasID = value, true
		case "retry":
			event.Retry = value
		}
	}
}

type sseWriter struct {
	writer  http.ResponseWriter
	flusher *http.ResponseController
}

func newSSEWriter(writer http.ResponseWriter) *sseWriter {
	return &sseWriter{writer: writer, flusher: http.NewResponseController(writer)}
}

func (writer *sseWriter) Write(event sseEvent) error {
	var buffer bytes.Buffer
	for _, comment := range event.Comments {
		buffer.WriteString(":" + comment + "\n")
	}
	if event.Name != "" {
		buffer.WriteString("event: " + event.Name + "\n")
	}
	if event.HasID {
		buffer.WriteString("id: " + event.ID + "\n")
	}
	if event.Retry != "" {
		buffer.WriteString("retry: " + event.Retry + "\n")
	}
	if event.HasData {
		for _, line := range strings.Split(event.Data, "\n") {
			buffer.WriteString("data: " + line + "\n")
		}
	}
	buffer.WriteString("\n")
	if _, err := writer.writer.Write(buffer.Bytes()); err != nil {
		return err
	}
	// A writer that cannot flush still delivers the event when it ends.
	_ = writer.flusher.Flush()
	return nil
}

func sseHeaders(header http.Header) {
	header.Set("Content-Type", "text/event-stream")
	header.Set("Cache-Control", "no-cache, no-store")
	header.Set("X-Accel-Buffering", "no")
}
