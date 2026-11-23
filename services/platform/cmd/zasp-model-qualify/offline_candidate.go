package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/zasp-ai/zasp-sec/services/platform/aigateway"
)

func candidateInput(path string, max int64, ownerOnly bool) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil || !st.Mode().IsRegular() || st.Size() > max || ownerOnly && st.Mode().Perm()&0077 != 0 {
		return nil, errors.New("invalid offline qualification input")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, errors.New("offline qualification input unavailable")
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !os.SameFile(st, opened) {
		return nil, errors.New("offline input changed")
	}
	data, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(data)) > max {
		return nil, errors.New("invalid offline input size")
	}
	return data, nil
}

func runOfflineCandidate(raw, sig, key []byte, corpusPath string, scope [3]string) error {
	token, err := candidateInput(os.Getenv("ZASP_QUALIFICATION_VLLM_TOKEN_FILE"), 8193, true)
	if err != nil {
		return err
	}
	defer clear(token)
	data, err := candidateInput(corpusPath, 8<<20, false)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Hour)
	defer cancel()
	report, err := aigateway.MeasureOfflineCandidate(ctx, raw, sig, key, scope, strings.TrimSuffix(string(token), "\n"), data)
	if err != nil {
		return errors.New("offline candidate or corpus rejected")
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))
	if !report.Measurement.Qualified {
		return errors.New("candidate did not meet the measured qualification criteria")
	}
	return nil
}
