package jawsauth

import (
	"testing"
	"time"
)

func waitFor[T any](t *testing.T, ch <-chan T, msg string) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-time.After(30 * time.Second):
		t.Fatal(msg)
	}
	var zero T
	return zero
}
