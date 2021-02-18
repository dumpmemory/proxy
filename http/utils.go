package http

import (
	"fmt"
)

func errInfo(addr string, err error) string {
	return fmt.Sprintf("; addr=%s, err=%v", addr, err)
}
