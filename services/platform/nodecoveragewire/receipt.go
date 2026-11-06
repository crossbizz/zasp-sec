package nodecoveragewire

import (
	"encoding/json"
	"regexp"
	"time"
)

var productID = regexp.MustCompile(`^pid_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func validReceipt(v Receipt) bool {
	if v.Disposition == "expired_not_committed" && v.ResolvedAt.Before(v.ExpiresAt) {
		return false
	}
	return productID.MatchString(v.SensorID) && v.SensorID != "pid_00000000-0000-0000-0000-000000000000" && v.Sequence > 0 && coverageBinding.MatchString(v.RequestDigest) && (v.Disposition == "accepted" || v.Disposition == "expired_not_committed") && validInstant(v.ResolvedAt) && validInstant(v.SourceObservedAt) && validInstant(v.ExpiresAt) && !v.ResolvedAt.Before(v.SourceObservedAt.Add(-5*time.Second)) && !v.ExpiresAt.Before(v.SourceObservedAt.Add(6*time.Second)) && !v.ExpiresAt.After(v.SourceObservedAt.Add(300*time.Second))
}
func ParseReceipt(raw []byte) (Receipt, error) {
	var v Receipt
	if strictDecode(raw, &v, 16384) != nil || !validReceipt(v) {
		return Receipt{}, ErrInvalid
	}
	return v, nil
}
func MarshalReceipt(v Receipt) ([]byte, error) {
	if !validReceipt(v) {
		return nil, ErrInvalid
	}
	b, e := json.Marshal(v)
	if e != nil || len(b) > 16384 {
		return nil, ErrInvalid
	}
	return b, nil
}
