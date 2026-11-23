package demodata

import (
	"fmt"
	"net/http"
	"slices"
	"sync"
	"testing"
)

func TestReplayRecordsConcurrentUnansweredRequests(t *testing.T) {
	replay := newReplay(&HTTPSource{Routes: []Route{{Path: "/present", Body: []byte(`{}`)}}}, Target{})
	client := &http.Client{Transport: replay}
	paths := []string{"/missing/b", "/present", "/missing/a"}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i := range 24 {
		workers.Go(func() {
			<-start
			path := paths[i%len(paths)]
			resp, err := client.Get(fmt.Sprintf("https://fixture.example%s?caller=%d", path, i))
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
			wantStatus := http.StatusNotFound
			if path == "/present" {
				wantStatus = http.StatusOK
			}
			if resp.StatusCode != wantStatus {
				t.Errorf("GET %s returned %d, want %d", path, resp.StatusCode, wantStatus)
			}
			seen := replay.unansweredRequests()
			if !slices.IsSorted(seen) || (resp.StatusCode == http.StatusNotFound && !slices.Contains(seen, "GET fixture.example"+path)) {
				t.Errorf("unexpected unanswered requests after GET %s: %v", path, seen)
			}
		})
	}
	close(start)
	workers.Wait()
	want := []string{"GET fixture.example/missing/a", "GET fixture.example/missing/b"}
	if got := replay.unansweredRequests(); !slices.Equal(got, want) {
		t.Errorf("unanswered requests = %v, want %v", got, want)
	}
}
