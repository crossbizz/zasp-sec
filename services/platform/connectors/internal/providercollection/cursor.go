package providercollection

import (
	"crypto/sha256"
	"fmt"
	"strconv"

	"github.com/zasp-ai/zasp-sec/services/platform/connectors/collection"
)

func CursorBinding(provider collection.Provider, subject collection.SubjectBinding, phase string, page int, continuation string) string {
	digest := sha256.Sum256([]byte(string(provider) + "\x1f" + subject.Kind + "\x1f" + subject.ID + "\x1f" + phase + "\x1f" + strconv.Itoa(page) + "\x1f" + continuation))
	return fmt.Sprintf("%x", digest[:8])
}

func CompleteCursorBinding(provider collection.Provider, subject collection.SubjectBinding) string {
	digest := sha256.Sum256([]byte(string(provider) + "\x1f" + subject.Kind + "\x1f" + subject.ID + "\x1fcomplete"))
	return fmt.Sprintf("%x", digest[:8])
}
