package apiserver

import "net/http"

func NewCompositionWithAuditExports(dependencies Dependencies, exports http.Handler) (http.Handler, error) {
	if _, valid := handlerIdentity(exports); !valid {
		return nil, ErrInvalidComposition
	}
	return newComposition(dependencies, exports)
}
