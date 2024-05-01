package wallet

import "errors"

var (
	// ErrSignatureMisMatch signature is incorrect
	ErrSignatureMisMatch = errors.New("signature does not match")
)
