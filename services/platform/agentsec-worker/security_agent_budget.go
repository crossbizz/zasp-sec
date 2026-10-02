package main

import (
	"bytes"
	"encoding/json"
	"math"
	"math/big"
	"strconv"
	"strings"
)

// A nil usage means unknown, never a zero-cost response. These are reported
// OpenRouter credits, not USD or a bound on separate upstream BYOK billing.
type securityAgentBudgetUsage struct {
	PromptTokens, CompletionTokens, TotalTokens, CostNanoCredits int64
}

func securityAgentPlannerUsage(body []byte, model string) *securityAgentBudgetUsage {
	response, ok := securityAgentBudgetObject(body)
	if !ok {
		return nil
	}
	var returnedModel string
	if json.Unmarshal(response["model"], &returnedModel) != nil || returnedModel != model {
		return nil
	}
	fields, ok := securityAgentBudgetObject(response["usage"])
	if !ok {
		return nil
	}
	usage := &securityAgentBudgetUsage{}
	for key, destination := range map[string]*int64{"prompt_tokens": &usage.PromptTokens, "completion_tokens": &usage.CompletionTokens, "total_tokens": &usage.TotalTokens} {
		raw := bytes.TrimSpace(fields[key])
		if len(raw) == 0 || bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, destination) != nil || *destination < 0 {
			return nil
		}
	}
	if usage.PromptTokens > math.MaxInt64-usage.CompletionTokens || usage.PromptTokens+usage.CompletionTokens != usage.TotalTokens {
		return nil
	}
	usage.CostNanoCredits, ok = securityAgentCostNanoCredits(fields["cost"])
	if !ok {
		return nil
	}
	return usage
}

// Decode exact keys and reject duplicates. Provider extension fields are
// allowed, but cannot overwrite a previously decoded accounting field.
func securityAgentBudgetObject(body []byte) (map[string]json.RawMessage, bool) {
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, false
		}
		key, ok := token.(string)
		if !ok {
			return nil, false
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, false
		}
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, false
		}
		fields[key] = value
	}
	if token, err := decoder.Token(); err != nil || token != json.Delim('}') || !jsonDecoderAtEOF(decoder) {
		return nil, false
	}
	return fields, true
}

func securityAgentCostNanoCredits(raw []byte) (int64, bool) {
	value := strings.TrimSpace(string(raw))
	// Bound big-number work before parsing an untrusted decimal exponent.
	if len(value) == 0 || len(value) > 128 || value[0] < '0' || value[0] > '9' || !json.Valid([]byte(value)) {
		return 0, false
	}
	if position := strings.IndexAny(value, "eE"); position >= 0 {
		exponent, err := strconv.ParseInt(value[position+1:], 10, 32)
		if err != nil || exponent < -1000 || exponent > 1000 {
			return 0, false
		}
	}
	credits, ok := new(big.Rat).SetString(value)
	if !ok || credits.Sign() < 0 {
		return 0, false
	}
	credits.Mul(credits, big.NewRat(1000000000, 1))
	whole, remainder := new(big.Int), new(big.Int)
	whole.QuoRem(credits.Num(), credits.Denom(), remainder)
	if remainder.Sign() != 0 {
		whole.Add(whole, big.NewInt(1))
	}
	if !whole.IsInt64() {
		return 0, false
	}
	return whole.Int64(), true
}
