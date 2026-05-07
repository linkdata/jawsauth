package jawsauth

import (
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

func TestOAuth2RequestDebugAttrsRedactsRequestData(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://provider.example/token?code=secret-code&client_id=client", strings.NewReader("grant_type=refresh_token&refresh_token=refresh-secret&client_secret=client-secret&client_id=client&empty_token="))
	req.Header.Set("Authorization", "Bearer access-secret")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Trace", "trace-id")

	attrs := testDebugAttrsMap(oauth2RequestDebugAttrs(req))
	if attrs["request_url"] != "https://provider.example/token?client_id=client&code=%5Bredacted%5D" {
		t.Fatal(attrs["request_url"])
	}
	headers, ok := attrs["request_headers"].(map[string][]string)
	if !ok {
		t.Fatal("missing headers")
	}
	if got := headers["Authorization"]; len(got) != 1 || got[0] != debugRedactedValue {
		t.Fatal(got)
	}
	if got := headers["X-Trace"]; len(got) != 1 || got[0] != "trace-id" {
		t.Fatal(got)
	}
	form, ok := attrs["request_form_data"].(url.Values)
	if !ok {
		t.Fatal("missing form data")
	}
	if got := form["refresh_token"]; len(got) != 1 || got[0] != debugRedactedValue {
		t.Fatal(got)
	}
	if got := form["client_secret"]; len(got) != 1 || got[0] != debugRedactedValue {
		t.Fatal(got)
	}
	if got := form["client_id"]; len(got) != 1 || got[0] != "client" {
		t.Fatal(got)
	}
	if got := form["empty_token"]; len(got) != 1 || got[0] != "" {
		t.Fatal(got)
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "grant_type=refresh_token&refresh_token=refresh-secret&client_secret=client-secret&client_id=client&empty_token=" {
		t.Fatal(string(body))
	}
}

func TestRequestBodyDebugAttrsJSONAndFallbacks(t *testing.T) {
	attrs := testDebugAttrsMap(requestBodyDebugAttrs("application/json", []byte(`{"client_id":"client","client_secret":"secret","items":[{"password":"secret"},1]}`)))
	data, ok := attrs["request_json_data"].(map[string]any)
	if !ok {
		t.Fatal("missing json data")
	}
	if data["client_id"] != "client" {
		t.Fatal(data["client_id"])
	}
	if data["client_secret"] != debugRedactedValue {
		t.Fatal(data["client_secret"])
	}
	items, ok := data["items"].([]any)
	if !ok || len(items) != 2 {
		t.Fatal(data["items"])
	}
	item, ok := items[0].(map[string]any)
	if !ok {
		t.Fatal(items[0])
	}
	if item["password"] != debugRedactedValue {
		t.Fatal(item["password"])
	}

	attrs = testDebugAttrsMap(requestBodyDebugAttrs("application/json", []byte(`{`)))
	if attrs["request_body_parse_error"] == "" {
		t.Fatal("missing json parse error")
	}
	if attrs["request_body"] != "{" {
		t.Fatal(attrs["request_body"])
	}

	attrs = testDebugAttrsMap(requestBodyDebugAttrs("application/x-www-form-urlencoded", []byte(`client_secret=%zz`)))
	if attrs["request_body_parse_error"] == "" {
		t.Fatal("missing form parse error")
	}
	if attrs["request_body"] != "client_secret=%zz" {
		t.Fatal(attrs["request_body"])
	}

	attrs = testDebugAttrsMap(requestBodyDebugAttrs("text/plain", []byte(strings.Repeat("x", debugRequestBodyLimit+1))))
	if attrs["request_body_truncated"] != true {
		t.Fatal(attrs["request_body_truncated"])
	}
	if got, _ := attrs["request_body"].(string); len(got) != debugRequestBodyLimit {
		t.Fatal(len(got))
	}
}

func TestDebugOAuth2TransportLogsRequestAndPreservesBody(t *testing.T) {
	logger := &testAuthDebugLogger{}
	var gotBody string
	provider := httptest.NewServer(http.HandlerFunc(func(hw http.ResponseWriter, hr *http.Request) {
		body, err := io.ReadAll(hr.Body)
		if err != nil {
			t.Error(err)
		}
		gotBody = string(body)
		hw.WriteHeader(http.StatusOK)
	}))
	defer provider.Close()

	jw := &jaws.Jaws{Debug: true, Logger: logger}
	srv := &Server{Jaws: jw}
	ctx := srv.oauth2Context(t.Context())
	client, ok := ctx.Value(oauth2.HTTPClient).(*http.Client)
	if !ok || client == nil {
		t.Fatal("missing debug client")
	}

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, provider.URL, strings.NewReader("client_secret=secret&grant_type=refresh_token"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if gotBody != "client_secret=secret&grant_type=refresh_token" {
		t.Fatal(gotBody)
	}
	record, ok := logger.info("jawsauth: oauth2 request")
	if !ok {
		t.Fatal("missing oauth2 request log")
	}
	attrs := testDebugAttrsMap(record.args)
	form, ok := attrs["request_form_data"].(url.Values)
	if !ok {
		t.Fatal("missing form data")
	}
	if got := form["client_secret"]; len(got) != 1 || got[0] != debugRedactedValue {
		t.Fatal(got)
	}
}

func TestDebugHTTPClientWrapsExistingClient(t *testing.T) {
	srv := &Server{}
	client := &http.Client{Timeout: time.Second}

	debugClient := srv.debugHTTPClient(client, &testAuthDebugLogger{})

	if debugClient == client {
		t.Fatal("debug client reused original client")
	}
	if debugClient.Timeout != time.Second {
		t.Fatal(debugClient.Timeout)
	}
	transport, ok := debugClient.Transport.(debugOAuth2Transport)
	if !ok {
		t.Fatal(debugClient.Transport)
	}
	if transport.next != http.DefaultTransport {
		t.Fatal(transport.next)
	}
}
