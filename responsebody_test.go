package jawsauth

import (
	"io"
	"net/http"
	"testing"
)

func closeTestBody(body io.Closer, errp *error) {
	if closeErr := body.Close(); *errp == nil && closeErr != nil {
		*errp = closeErr
	}
}

func closeResponseBody(t *testing.T, resp *http.Response) {
	t.Helper()
	if resp != nil && resp.Body != nil {
		if err := resp.Body.Close(); err != nil {
			t.Errorf("close response body: %v", err)
		}
	}
}
