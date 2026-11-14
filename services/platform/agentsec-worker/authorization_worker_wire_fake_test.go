package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgxpool"
)

// workerWireStatement is one simple-protocol statement the fake PostgreSQL
// server received: its text and its literal arguments, decoded.
type workerWireStatement struct {
	SQL  string
	Args []string
}

// workerWireReply is the fake server's answer to one statement: a single
// jsonb row, or a PostgreSQL error with the given SQLSTATE.
type workerWireReply struct {
	Row  json.RawMessage
	Code string
}

// workerWireServer speaks just enough of the PostgreSQL wire protocol for an
// authorization.WorkerExecutor whose pool runs in simple-protocol mode. It
// answers transaction control and the worker proof (set_config) itself and
// every other statement with handle.
// Nothing here is PostgreSQL: it lets the worker's own logic run against
// scripted native answers.
type workerWireServer struct {
	t          *testing.T
	mu         sync.Mutex
	statements []workerWireStatement
	handle     func(workerWireStatement) workerWireReply
}

func newWorkerWirePool(t *testing.T, handle func(workerWireStatement) workerWireReply) (*pgxpool.Pool, *workerWireServer) {
	t.Helper()
	server := &workerWireServer{t: t, handle: handle}
	config, err := pgxpool.ParseConfig("postgres://worker@127.0.0.1:5432/fake?sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	config.MaxConns = 1
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	config.ConnConfig.DialFunc = func(context.Context, string, string) (net.Conn, error) {
		client, backend := net.Pipe()
		go server.serve(backend)
		return client, nil
	}
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool, server
}

// Statements returns every statement received other than transaction control
// and pings, in order: the handler's statements and the worker proofs.
func (s *workerWireServer) Statements() []workerWireStatement {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]workerWireStatement(nil), s.statements...)
}

func (s *workerWireServer) serve(conn net.Conn) {
	defer conn.Close()
	backend := pgproto3.NewBackend(conn, conn)
	if _, err := backend.ReceiveStartupMessage(); err != nil {
		return
	}
	backend.Send(&pgproto3.AuthenticationOk{})
	for name, value := range map[string]string{"standard_conforming_strings": "on", "client_encoding": "UTF8", "server_version": "17.0", "DateStyle": "ISO, MDY"} {
		backend.Send(&pgproto3.ParameterStatus{Name: name, Value: value})
	}
	backend.Send(&pgproto3.BackendKeyData{ProcessID: 1, SecretKey: []byte{0, 0, 0, 1}})
	status := byte('I')
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: status})
	if backend.Flush() != nil {
		return
	}
	for {
		message, err := backend.Receive()
		if err != nil {
			return
		}
		query, ok := message.(*pgproto3.Query)
		if !ok {
			return
		}
		text := strings.TrimSpace(query.String)
		lower := strings.ToLower(text)
		switch {
		case text == "" || text == ";" || strings.HasPrefix(text, "--"):
			backend.Send(&pgproto3.EmptyQueryResponse{})
		case strings.HasPrefix(lower, "begin"):
			status = 'T'
			backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("BEGIN")})
		case strings.HasPrefix(lower, "commit"):
			tag := "COMMIT"
			if status == 'E' {
				tag = "ROLLBACK"
			}
			status = 'I'
			backend.Send(&pgproto3.CommandComplete{CommandTag: []byte(tag)})
		case strings.HasPrefix(lower, "rollback"):
			status = 'I'
			backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("ROLLBACK")})
		case strings.Contains(text, "set_config('zasp.worker_proof'"):
			s.mu.Lock()
			s.statements = append(s.statements, workerWireStatement{SQL: text, Args: workerWireLiterals(text)})
			s.mu.Unlock()
			backend.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("set_config"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1}}})
			backend.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("proof")}})
			backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
		default:
			statement := workerWireStatement{SQL: text, Args: workerWireLiterals(text)}
			s.mu.Lock()
			s.statements = append(s.statements, statement)
			s.mu.Unlock()
			reply := s.handle(statement)
			if reply.Code != "" {
				if status == 'T' {
					status = 'E'
				}
				backend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: reply.Code, Message: "scripted failure"})
			} else {
				backend.Send(&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{Name: []byte("result"), DataTypeOID: 3802, DataTypeSize: -1, TypeModifier: -1}}})
				backend.Send(&pgproto3.DataRow{Values: [][]byte{reply.Row}})
				backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
			}
		}
		backend.Send(&pgproto3.ReadyForQuery{TxStatus: status})
		if backend.Flush() != nil {
			return
		}
	}
}

// workerWireLiterals returns the quoted literals of a sanitized simple
// statement in order; a bytea literal (\x...) is decoded.
func workerWireLiterals(text string) []string {
	var literals []string
	for i := 0; i < len(text); i++ {
		if text[i] != '\'' {
			continue
		}
		var b strings.Builder
		for i++; i < len(text); i++ {
			if text[i] == '\'' {
				if i+1 < len(text) && text[i+1] == '\'' {
					b.WriteByte('\'')
					i++
					continue
				}
				break
			}
			b.WriteByte(text[i])
		}
		literal := b.String()
		if strings.HasPrefix(literal, `\x`) {
			if decoded, err := hex.DecodeString(literal[2:]); err == nil {
				literal = string(decoded)
			}
		}
		literals = append(literals, literal)
	}
	return literals
}
