package jawsauth

import (
	"testing"
	"time"

	"github.com/linkdata/jaws"
)

func newTestJaws(t *testing.T) *jaws.Jaws {
	t.Helper()
	jw, err := jaws.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(jw.Close)
	return jw
}

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
