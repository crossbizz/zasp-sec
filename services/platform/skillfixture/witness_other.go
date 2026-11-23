//go:build !linux

package skillfixture

import "context"

func Child() error                                         { return ErrRefused }
func Witness(ctx context.Context, c Claim) (Result, error) { return Result{}, ErrRefused }
