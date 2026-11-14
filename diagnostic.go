package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"syscall"
)

// Only locally constructed diagnostics may cross the public JSON boundary.
// Never include upstream bodies, URL errors, filenames, or identity fields.
type diagnostic string

func (d diagnostic) Error() string { return string(d) }
func safeReason(err error) string {
	var d diagnostic
	if errors.As(err, &d) {
		return string(d)
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "request timed out"
	}
	if errors.Is(err, context.Canceled) {
		return "request was canceled"
	}
	if errors.Is(err, os.ErrPermission) {
		return "permission denied"
	}
	if errors.Is(err, os.ErrNotExist) {
		return "local file or directory is missing"
	}
	if errors.Is(err, os.ErrExist) {
		return "local file already exists"
	}
	if errors.Is(err, syscall.ENOSPC) {
		return "no space left on local storage"
	}
	if errors.Is(err, syscall.EROFS) {
		return "local storage is read-only"
	}
	if errors.Is(err, syscall.EIO) {
		return "local storage input/output error"
	}
	return "operation failed"
}
func httpFailure(status int) error {
	reason := http.StatusText(status)
	if reason == "" {
		reason = "unexpected response"
	}
	return diagnostic(fmt.Sprintf("HTTP %d (%s)", status, reason))
}
