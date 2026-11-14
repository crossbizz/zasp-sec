// Package guardrail decides what to do with one model interaction (the text
// going into a model or coming out of it): allow it, redact parts of it, or
// block it. It is the engine of the guardrail decision API, which a gateway
// the customer already runs calls before it forwards a request or a response.
//
// Every detector is deterministic: regular expressions (RE2, linear time),
// fixed phrase lists and checksums. No model is called and nothing is
// stored. The detectors are heuristics; they catch the common, literal forms
// of prompt injection and of sensitive data and they will miss paraphrases
// and obfuscations they do not name. Each rule says what it matches.
package guardrail

import (
	"encoding/base64"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

// MaxTextBytes is the largest interaction text a decision takes.
const MaxTextBytes = 32 * 1024

// Direction says which way the text travels.
type Direction string

const (
	// DirectionInput is text on its way into a model: a prompt, a retrieved
	// document, a tool result.
	DirectionInput Direction = "input"
	// DirectionOutput is text a model produced.
	DirectionOutput Direction = "output"
)

// Mode is what a matched rule does.
type Mode string

const (
	// ModeBlock stops the interaction.
	ModeBlock Mode = "block"
	// ModeRedact replaces the matched text and lets the rest through.
	ModeRedact Mode = "redact"
	// ModeMonitor reports the match and changes nothing.
	ModeMonitor Mode = "monitor"
	// ModeOff ignores the rule.
	ModeOff Mode = "off"
)

// Categories of rules.
const (
	CategoryPromptInjection = "prompt_injection"
	CategorySensitiveData   = "sensitive_data"
)

// Rule is one detector. A rule that is not Redactable finds an intent, not a
// span that can be removed, so it cannot be set to redact.
type Rule struct {
	ID          string
	Category    string
	Description string
	DefaultMode Mode
	Redactable  bool
}

// Rule identifiers.
const (
	RuleInstructionOverride = "injection.instruction_override"
	RuleRoleSwitch          = "injection.role_switch"
	RuleHiddenText          = "injection.hidden_text"
	RuleToolCall            = "injection.tool_call"
	RuleEmail               = "pii.email"
	RulePhone               = "pii.phone"
	RuleCreditCard          = "pii.credit_card"
	RuleSSN                 = "pii.us_ssn"
	RuleAWSAccessKeyID      = "secret.aws_access_key_id"
	RulePrivateKey          = "secret.private_key"
	RuleBearerToken         = "secret.bearer_token"
)

var rules = []Rule{
	{ID: RuleInstructionOverride, Category: CategoryPromptInjection, DefaultMode: ModeBlock, Description: "Text that tells the model to ignore, forget, disregard or override its earlier or system instructions."},
	{ID: RuleRoleSwitch, Category: CategoryPromptInjection, DefaultMode: ModeBlock, Description: "Chat-template role markers inside the text (a forged system or assistant turn) and requests to switch into an unrestricted persona."},
	{ID: RuleHiddenText, Category: CategoryPromptInjection, DefaultMode: ModeBlock, Description: "Invisible or disguised instructions: zero-width and bidirectional control characters, Unicode tag characters, instructions inside an HTML comment, and base64 that decodes to an instruction override."},
	{ID: RuleToolCall, Category: CategoryPromptInjection, DefaultMode: ModeBlock, Description: "Text that carries a tool or function call in a model's own call syntax, so that a document or a tool result can make the agent call a tool."},
	{ID: RuleEmail, Category: CategorySensitiveData, DefaultMode: ModeRedact, Redactable: true, Description: "Email addresses."},
	{ID: RulePhone, Category: CategorySensitiveData, DefaultMode: ModeRedact, Redactable: true, Description: "Phone numbers in international (+country) form and in North American form."},
	{ID: RuleCreditCard, Category: CategorySensitiveData, DefaultMode: ModeRedact, Redactable: true, Description: "Payment card numbers of 13 to 19 digits that pass the Luhn checksum."},
	{ID: RuleSSN, Category: CategorySensitiveData, DefaultMode: ModeRedact, Redactable: true, Description: "US Social Security numbers written with dashes, excluding ranges that are never issued."},
	{ID: RuleAWSAccessKeyID, Category: CategorySensitiveData, DefaultMode: ModeRedact, Redactable: true, Description: "AWS access key IDs (AKIA and ASIA prefixes)."},
	{ID: RulePrivateKey, Category: CategorySensitiveData, DefaultMode: ModeRedact, Redactable: true, Description: "PEM private key blocks, from the BEGIN line to the END line when it is present."},
	{ID: RuleBearerToken, Category: CategorySensitiveData, DefaultMode: ModeRedact, Redactable: true, Description: "Bearer tokens in an Authorization value and JSON Web Tokens."},
}

// Rules returns the rule catalog in a fixed order.
func Rules() []Rule { return append([]Rule(nil), rules...) }

// RuleByID returns one rule of the catalog.
func RuleByID(id string) (Rule, bool) {
	for _, rule := range rules {
		if rule.ID == id {
			return rule, true
		}
	}
	return Rule{}, false
}

// ValidMode reports whether a rule can be set to a mode.
func ValidMode(rule Rule, mode Mode) bool {
	switch mode {
	case ModeBlock, ModeMonitor, ModeOff:
		return true
	case ModeRedact:
		return rule.Redactable
	}
	return false
}

// Match is one finding: the rule and the byte range of the text it covers.
type Match struct {
	RuleID     string
	Start, End int
}

var (
	// Instruction override. The verb, an optional determiner, a reference to
	// what came before, and the thing to be ignored.
	instructionOverridePattern = regexp.MustCompile(`(?i)\b(?:ignore|disregard|forget|override|bypass|do\s+not\s+follow|don'?t\s+follow|stop\s+following)\b[^.\n]{0,40}?\b(?:previous|prior|above|earlier|preceding|former|original|initial|system|developer|your|all|any)\b[^.\n]{0,30}?\b(?:instructions?|prompts?|rules?|directions?|guidelines?|polic(?:y|ies)|constraints?|guardrails?|restrictions?)\b`)
	newInstructionsPattern     = regexp.MustCompile(`(?i)\b(?:new|updated|real|actual)\s+(?:system\s+)?instructions?\s*(?::|follow\b|are\b)`)
	revealPromptPattern        = regexp.MustCompile(`(?i)\b(?:reveal|print|show|repeat|output|leak|display)\b[^.\n]{0,30}?\b(?:your|the)\s+(?:system\s+prompt|hidden\s+prompt|initial\s+instructions|system\s+instructions|system\s+message)\b`)

	// Role switch: forged turns in common chat templates, and persona requests.
	roleMarkerPattern = regexp.MustCompile(`(?i)(?:<\|im_start\|>\s*(?:system|assistant)|<\|(?:system|assistant)\|>|<<SYS>>|\[/?INST\]|<\s*/?\s*system\s*>|(?:^|\n)\s*#{2,}\s*(?:system|assistant)\s*:?\s*(?:\n|$)|(?:^|\n)\s*system\s*:\s*\S|\bBEGIN\s+SYSTEM\s+PROMPT\b)`)
	personaPattern    = regexp.MustCompile(`(?i)\b(?:you\s+are\s+now|from\s+now\s+on,?\s+you\s+are|act\s+as|pretend\s+(?:to\s+be|you\s+are)|roleplay\s+as|switch\s+to)\b[^.\n]{0,40}?\b(?:DAN|jailbroken|unrestricted|unfiltered|uncensored|developer\s+mode|god\s+mode|no\s+(?:rules|restrictions|filters|limits)|without\s+(?:any\s+)?(?:rules|restrictions|filters|limits))\b`)

	// Hidden text.
	htmlCommentPattern = regexp.MustCompile(`(?s)<!--.*?-->`)
	base64Pattern      = regexp.MustCompile(`[A-Za-z0-9+/]{32,}={0,2}`)

	// Tool-call injection: a model's own call syntax inside content.
	toolCallPattern = regexp.MustCompile(`(?i)(?:<\s*tool_calls?\s*>|<\s*function_calls?\s*>|<\s*invoke\s+name\s*=|<\|tool_call\|>|"tool_calls"\s*:\s*\[|"function_call"\s*:\s*\{|"type"\s*:\s*"(?:tool_use|function_call)"|\b(?:call|invoke|use|run|execute)\s+the\s+(?:tool|function)\s+[\x60"']?[A-Za-z_][A-Za-z0-9_.-]{1,63}[\x60"']?\s+(?:with|using|now|immediately))`)

	// Sensitive data.
	emailPattern       = regexp.MustCompile(`[A-Za-z0-9][A-Za-z0-9._%+-]{0,63}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*\.[A-Za-z]{2,24}`)
	phonePattern       = regexp.MustCompile(`(?:\+[1-9][0-9]{0,2}[ .-]?(?:\(?[0-9]{1,4}\)?[ .-]?){2,4}[0-9]{2,4}|\(?[2-9][0-9]{2}\)?[ .-][2-9][0-9]{2}[ .-][0-9]{4})`)
	cardPattern        = regexp.MustCompile(`[0-9](?:[ -]?[0-9]){12,18}`)
	ssnPattern         = regexp.MustCompile(`[0-9]{3}-[0-9]{2}-[0-9]{4}`)
	awsKeyPattern      = regexp.MustCompile(`(?:AKIA|ASIA)[A-Z0-9]{16}`)
	privateKeyPattern  = regexp.MustCompile(`(?s)-----BEGIN (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----(?:.*?-----END (?:[A-Z0-9]+ ){0,3}PRIVATE KEY(?: BLOCK)?-----)?`)
	bearerPattern      = regexp.MustCompile(`(?i)\bbearer\s+[A-Za-z0-9._~+/-]{20,}=*`)
	jwtPattern         = regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`)
	overrideInDecoding = []*regexp.Regexp{newInstructionsPattern, revealPromptPattern, personaPattern}
)

func isWordByte(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'A' && value <= 'Z' || value >= 'a' && value <= 'z' || value == '_'
}

// bounded reports whether [start,end) is not glued to a longer run of word
// characters or digits, so that a number inside a longer identifier is not
// taken for a card, a phone number or a key.
func bounded(text string, start, end int) bool {
	return (start == 0 || !isWordByte(text[start-1])) && (end == len(text) || !isWordByte(text[end]))
}

func luhn(digits []byte) bool {
	sum, double := 0, false
	for index := len(digits) - 1; index >= 0; index-- {
		value := int(digits[index] - '0')
		if double {
			value *= 2
			if value > 9 {
				value -= 9
			}
		}
		sum += value
		double = !double
	}
	return sum%10 == 0
}

func validSSN(value string) bool {
	area, group, serial := value[0:3], value[4:6], value[7:11]
	return area != "000" && area != "666" && area[0] != '9' && group != "00" && serial != "0000"
}

// hiddenRune reports whether a rune is invisible or changes the direction of
// the text: zero-width characters, bidirectional controls and Unicode tags.
func hiddenRune(value rune) bool {
	switch {
	case value >= 0x200B && value <= 0x200F, value >= 0x202A && value <= 0x202E, value >= 0x2060 && value <= 0x2064, value >= 0x2066 && value <= 0x2069, value == 0xFEFF, value >= 0xE0000 && value <= 0xE007F:
		return true
	}
	return false
}

var negationPattern = regexp.MustCompile(`(?i)(?:\bnever|\bnot|n't|\bwithout)\s+(?:ever\s+)?$`)

// negated reports whether the verb at start is preceded by a negation, as in
// "do not ignore" or "never disregard". The verbs that carry their own
// negation ("do not follow") start at the negation and are not affected.
func negated(text string, start int) bool {
	from := start - 16
	if from < 0 {
		from = 0
	}
	return negationPattern.MatchString(text[from:start])
}

func overrideText(text string) bool {
	for _, location := range instructionOverridePattern.FindAllStringIndex(text, 16) {
		if !negated(text, location[0]) {
			return true
		}
	}
	for _, pattern := range overrideInDecoding {
		if pattern.MatchString(text) {
			return true
		}
	}
	return false
}

func appendAll(matches []Match, rule string, pattern *regexp.Regexp, text string) []Match {
	for _, location := range pattern.FindAllStringIndex(text, 256) {
		matches = append(matches, Match{RuleID: rule, Start: location[0], End: location[1]})
	}
	return matches
}

// Detect returns every match in the text, ordered by position. The text must
// be valid UTF-8 of at most MaxTextBytes; anything else returns nil and
// false. The direction is part of the interaction and is reported with the
// decision; the same rules apply to both directions, because an injected
// instruction can arrive in a prompt and can be relayed in a model's output.
func Detect(text string, direction Direction) ([]Match, bool) {
	if len(text) > MaxTextBytes || !utf8.ValidString(text) || direction != DirectionInput && direction != DirectionOutput {
		return nil, false
	}
	var matches []Match
	// Each expression runs only when a word it cannot match without is in
	// the text; ordinary text skips most of them.
	lower := strings.ToLower(text)
	has := func(words ...string) bool {
		for _, word := range words {
			if strings.Contains(lower, word) {
				return true
			}
		}
		return false
	}
	if has("ignore", "disregard", "forget", "override", "bypass", "follow") {
		for _, location := range instructionOverridePattern.FindAllStringIndex(text, 256) {
			// "never ignore your previous instructions" defends the
			// instructions; it is not an attempt to override them.
			if !negated(text, location[0]) {
				matches = append(matches, Match{RuleID: RuleInstructionOverride, Start: location[0], End: location[1]})
			}
		}
	}
	if has("instruction") {
		matches = appendAll(matches, RuleInstructionOverride, newInstructionsPattern, text)
	}
	if has("system", "hidden prompt", "initial instructions") {
		matches = appendAll(matches, RuleInstructionOverride, revealPromptPattern, text)
	}
	if has("system", "assistant", "inst]", "<|", "<<sys") {
		matches = appendAll(matches, RuleRoleSwitch, roleMarkerPattern, text)
	}
	if has("you are", "act as", "pretend", "roleplay", "switch to") {
		matches = appendAll(matches, RuleRoleSwitch, personaPattern, text)
	}
	if has("tool", "function", "invoke") {
		matches = appendAll(matches, RuleToolCall, toolCallPattern, text)
	}

	// Hidden characters: one match per run.
	runStart := -1
	for index, value := range text {
		if hiddenRune(value) {
			if runStart < 0 {
				runStart = index
			}
			continue
		}
		if runStart >= 0 {
			matches = append(matches, Match{RuleID: RuleHiddenText, Start: runStart, End: index})
			runStart = -1
		}
	}
	if runStart >= 0 {
		matches = append(matches, Match{RuleID: RuleHiddenText, Start: runStart, End: len(text)})
	}
	// An instruction inside an HTML comment is not shown to a person.
	for _, location := range htmlCommentPattern.FindAllStringIndex(text, 64) {
		if overrideText(text[location[0]:location[1]]) {
			matches = append(matches, Match{RuleID: RuleHiddenText, Start: location[0], End: location[1]})
		}
	}
	// Base64 that decodes to an instruction override. At most 32 candidates
	// are decoded, so the cost stays bounded.
	for _, location := range base64Pattern.FindAllStringIndex(text, 32) {
		candidate := strings.TrimRight(text[location[0]:location[1]], "=")
		if len(candidate)%4 == 1 {
			// One character cannot end a base64 group: drop it.
			candidate = candidate[:len(candidate)-1]
		}
		decoded, err := base64.RawStdEncoding.DecodeString(candidate)
		if err == nil && utf8.Valid(decoded) && overrideText(string(decoded)) {
			matches = append(matches, Match{RuleID: RuleHiddenText, Start: location[0], End: location[1]})
		}
	}

	if strings.Contains(text, "@") {
		matches = appendAll(matches, RuleEmail, emailPattern, text)
	}
	matches = appendAll(matches, RulePrivateKey, privateKeyPattern, text)
	if has("bearer") {
		matches = appendAll(matches, RuleBearerToken, bearerPattern, text)
	}
	for _, location := range jwtPattern.FindAllStringIndex(text, 256) {
		if bounded(text, location[0], location[1]) {
			matches = append(matches, Match{RuleID: RuleBearerToken, Start: location[0], End: location[1]})
		}
	}
	for _, location := range awsKeyPattern.FindAllStringIndex(text, 256) {
		if bounded(text, location[0], location[1]) {
			matches = append(matches, Match{RuleID: RuleAWSAccessKeyID, Start: location[0], End: location[1]})
		}
	}
	cards := make([][2]int, 0, 4)
	for _, location := range cardPattern.FindAllStringIndex(text, 256) {
		if !bounded(text, location[0], location[1]) {
			continue
		}
		digits := make([]byte, 0, 19)
		for index := location[0]; index < location[1]; index++ {
			if text[index] >= '0' && text[index] <= '9' {
				digits = append(digits, text[index])
			}
		}
		if len(digits) >= 13 && len(digits) <= 19 && luhn(digits) {
			matches = append(matches, Match{RuleID: RuleCreditCard, Start: location[0], End: location[1]})
			cards = append(cards, [2]int{location[0], location[1]})
		}
	}
	inCard := func(start, end int) bool {
		for _, card := range cards {
			if start < card[1] && end > card[0] {
				return true
			}
		}
		return false
	}
	for _, location := range ssnPattern.FindAllStringIndex(text, 256) {
		if bounded(text, location[0], location[1]) && validSSN(text[location[0]:location[1]]) && !inCard(location[0], location[1]) {
			matches = append(matches, Match{RuleID: RuleSSN, Start: location[0], End: location[1]})
		}
	}
	for _, location := range phonePattern.FindAllStringIndex(text, 256) {
		if !bounded(text, location[0], location[1]) || inCard(location[0], location[1]) {
			continue
		}
		digits := 0
		for index := location[0]; index < location[1]; index++ {
			if text[index] >= '0' && text[index] <= '9' {
				digits++
			}
		}
		if digits >= 10 && digits <= 15 {
			matches = append(matches, Match{RuleID: RulePhone, Start: location[0], End: location[1]})
		}
	}
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Start != matches[j].Start {
			return matches[i].Start < matches[j].Start
		}
		if matches[i].End != matches[j].End {
			return matches[i].End > matches[j].End
		}
		return matches[i].RuleID < matches[j].RuleID
	})
	return matches, true
}

// Decision values.
const (
	DecisionAllow  = "allow"
	DecisionRedact = "redact"
	DecisionBlock  = "block"
)

// MatchedRule is one rule that matched, with the mode it was applied in.
type MatchedRule struct {
	ID       string
	Category string
	Mode     Mode
	Count    int
}

// Decision is the outcome for one interaction. RedactedText is set only for
// DecisionRedact.
type Decision struct {
	Decision     string
	RedactedText string
	Rules        []MatchedRule
}

// Decide applies the modes to the matches. modes gives the mode of a rule;
// a rule it does not name (or names with a mode the rule cannot take) uses
// its default. A rule set to off is not reported. The interaction is blocked
// when any matched rule blocks; otherwise the spans of the rules that redact
// are replaced by "[REDACTED:<rule>]"; otherwise it is allowed.
func Decide(text string, matches []Match, modes map[string]Mode) Decision {
	effective := func(rule Rule) Mode {
		if mode, ok := modes[rule.ID]; ok && ValidMode(rule, mode) {
			return mode
		}
		return rule.DefaultMode
	}
	counts := map[string]int{}
	for _, match := range matches {
		counts[match.RuleID]++
	}
	result := Decision{Decision: DecisionAllow, Rules: []MatchedRule{}}
	redact := map[string]bool{}
	for _, rule := range rules {
		if counts[rule.ID] == 0 {
			continue
		}
		mode := effective(rule)
		if mode == ModeOff {
			continue
		}
		result.Rules = append(result.Rules, MatchedRule{ID: rule.ID, Category: rule.Category, Mode: mode, Count: counts[rule.ID]})
		switch mode {
		case ModeBlock:
			result.Decision = DecisionBlock
		case ModeRedact:
			redact[rule.ID] = true
			if result.Decision == DecisionAllow {
				result.Decision = DecisionRedact
			}
		}
	}
	if result.Decision != DecisionRedact {
		return result
	}
	// Replace the redacted spans, merging overlaps; the label of a merged
	// span is the rule of its first match.
	var builder strings.Builder
	builder.Grow(len(text))
	position := 0
	for _, match := range matches {
		if !redact[match.RuleID] || match.End <= position {
			continue
		}
		start := match.Start
		if start < position {
			start = position
		} else {
			builder.WriteString(text[position:start])
			builder.WriteString("[REDACTED:" + match.RuleID + "]")
		}
		position = match.End
	}
	builder.WriteString(text[position:])
	result.RedactedText = builder.String()
	return result
}
