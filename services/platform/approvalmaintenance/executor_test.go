package approvalmaintenance

import (
	"context"
	"errors"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/zasp-ai/zasp-sec/services/platform/authorization"
	"sync"
	"testing"
)

type executorChecker struct{}

func (executorChecker) Check(context.Context, authorization.CheckRequest) (authorization.Decision, error) {
	return authorization.Decision{}, ErrUnavailable
}
func TestExecutorRefusesIncompleteAuthorityBeforeDatabase(t *testing.T) {
	p := &pgxpool.Pool{}
	c := executorChecker{}
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0xa5
	}
	id := "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	pin := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	cases := []struct {
		pool              *pgxpool.Pool
		checker           authorization.Checker
		store, model, pin string
		key               []byte
	}{{nil, c, id, id, pin, key}, {p, nil, id, id, pin, key}, {p, c, "untrusted", id, pin, key}, {p, c, id, "untrusted", pin, key}, {p, c, id, id, "bad", key}, {p, c, id, id, pin, key[:31]}}
	for _, v := range cases {
		if e, err := NewExecutor(v.pool, v.checker, v.store, v.model, v.pin, v.key); e != nil || !errors.Is(err, ErrConfiguration) {
			t.Fatal("incomplete caller admitted")
		}
	}
}
func TestExecutorCopiesAndErasesItsOwnedSigningKey(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = 0xa5
	}
	e, err := NewExecutor(&pgxpool.Pool{}, executorChecker{}, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", key)
	if err != nil {
		t.Fatal(err)
	}
	clear(key)
	owned := e.key
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				copy, err := e.keySnapshot()
				if err == nil {
					if len(copy) != 32 {
						t.Error("partial key")
					}
					for _, b := range copy {
						if b != 0xa5 {
							t.Error("caller key alias or partial erase")
						}
					}
					clear(copy)
				}
			}
		}()
	}
	e.Close()
	wg.Wait()
	for _, b := range owned {
		if b != 0 {
			t.Fatal("owned signing key not erased")
		}
	}
	if _, err := e.keySnapshot(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed issuer remained available")
	}
	if err := e.Ready(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed issuer touched readiness")
	}
	if _, err := e.Invoke(context.Background(), NativeBeforeDelivery, nil, nil); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed issuer admitted signed decision")
	}
	e.Close()
}
