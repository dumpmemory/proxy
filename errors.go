package socks5

import "errors"

// ErrVersion error version
var ErrVersion = errors.New("invalid version")

// ErrMethod error method
var ErrMethod = errors.New("invalid method")
