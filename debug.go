package jawsauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/linkdata/jaws"
	"golang.org/x/oauth2"
)

const debugErrorBodyLimit = 2048
const debugRequestBodyLimit = 4096
const debugRedactedValue = "[redacted]"

func (srv *Server) debugLog(msg string, args ...any) {
	if logger := srv.debugLogger(); logger != nil {
		logger.Info(msg, args...)
	}
}

func (srv *Server) debugErrorLog(msg string, err error, args ...any) {
	if logger := srv.debugLogger(); logger != nil {
		logger.Info(msg, append(args, errorDebugAttrs(err)...)...)
	}
}

func (srv *Server) debugLogger() (logger jaws.Logger) {
	if srv != nil && srv.Jaws != nil && srv.Jaws.Debug {
		logger = srv.Jaws.Logger
	}
	return
}

type debugOAuth2Transport struct {
	logger jaws.Logger
	next   http.RoundTripper
}

func (transport debugOAuth2Transport) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	if transport.logger != nil {
		transport.logger.Info("jawsauth: oauth2 request", oauth2RequestDebugAttrs(req)...)
	}
	resp, err = transport.next.RoundTrip(req)
	return
}

func (srv *Server) debugHTTPClient(client *http.Client, logger jaws.Logger) (debugClient *http.Client) {
	debugClient = &http.Client{Transport: http.DefaultTransport}
	if client != nil {
		clientCopy := *client
		debugClient = &clientCopy
	}
	next := debugClient.Transport
	if next == nil {
		next = http.DefaultTransport
	}
	debugClient.Transport = debugOAuth2Transport{logger: logger, next: next}
	return
}

func oauth2RequestDebugAttrs(req *http.Request) (attrs []any) {
	attrs = []any{"request_nil", req == nil}
	if req != nil {
		attrs = append(attrs,
			"request_method", req.Method,
			"request_url", redactDebugURL(req.URL),
			"request_headers", redactDebugHeaders(req.Header),
		)
		if req.Body != nil {
			var body []byte
			var err error
			body, err = io.ReadAll(req.Body)
			req.Body = io.NopCloser(bytes.NewReader(body))
			attrs = append(attrs, "request_body_read_error", err)
			if err == nil {
				attrs = append(attrs, requestBodyDebugAttrs(req.Header.Get("Content-Type"), body)...)
			}
		}
	}
	return
}

func redactDebugURL(u *url.URL) (s string) {
	if u != nil {
		clone := *u
		clone.User = nil
		clone.RawQuery = redactDebugQuery(clone.Query()).Encode()
		s = clone.String()
	}
	return
}

func redactDebugQuery(values url.Values) (redacted url.Values) {
	redacted = make(url.Values, len(values))
	for k, vs := range values {
		redacted[k] = redactDebugValues(k, vs)
	}
	return
}

func redactDebugHeaders(header http.Header) (redacted map[string][]string) {
	redacted = make(map[string][]string, len(header))
	for k, vs := range header {
		redacted[k] = redactDebugValues(k, vs)
	}
	return
}

func redactDebugValues(key string, values []string) (redacted []string) {
	redacted = make([]string, len(values))
	for i, value := range values {
		redacted[i] = value
		if isSensitiveDebugKey(key) && value != "" {
			redacted[i] = debugRedactedValue
		}
	}
	return
}

func requestBodyDebugAttrs(contentType string, body []byte) (attrs []any) {
	attrs = []any{"request_body_len", len(body)}
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if len(body) != 0 {
		switch {
		case mediaType == "application/x-www-form-urlencoded":
			values, err := url.ParseQuery(string(body))
			if err == nil {
				attrs = append(attrs, "request_form_data", redactDebugQuery(values))
			} else {
				attrs = append(attrs, "request_body_parse_error", err.Error())
				attrs = append(attrs, redactDebugBodyText(body)...)
			}
		case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
			var value any
			err := json.Unmarshal(body, &value)
			if err == nil {
				attrs = append(attrs, "request_json_data", redactDebugJSONValue("", value))
			} else {
				attrs = append(attrs, "request_body_parse_error", err.Error())
				attrs = append(attrs, redactDebugBodyText(body)...)
			}
		default:
			attrs = append(attrs, redactDebugBodyText(body)...)
		}
	}
	return
}

func redactDebugBodyText(body []byte) (attrs []any) {
	text := string(body)
	if len(text) > debugRequestBodyLimit {
		text = text[:debugRequestBodyLimit]
		attrs = append(attrs, "request_body_truncated", true)
	}
	attrs = append(attrs, "request_body", text)
	return
}

func redactDebugJSONValue(key string, value any) (redacted any) {
	redacted = value
	if isSensitiveDebugKey(key) {
		redacted = debugRedactedValue
	} else {
		switch v := value.(type) {
		case map[string]any:
			m := make(map[string]any, len(v))
			for k, item := range v {
				m[k] = redactDebugJSONValue(k, item)
			}
			redacted = m
		case []any:
			sl := make([]any, len(v))
			for i, item := range v {
				sl[i] = redactDebugJSONValue(key, item)
			}
			redacted = sl
		}
	}
	return
}

func isSensitiveDebugKey(key string) (sensitive bool) {
	key = strings.ToLower(key)
	for _, marker := range []string{
		"authorization",
		"assertion",
		"code",
		"cookie",
		"password",
		"secret",
		"token",
		"verifier",
	} {
		if strings.Contains(key, marker) {
			sensitive = true
			return
		}
	}
	return
}

func errorDebugAttrs(err error) (attrs []any) {
	attrs = []any{"err", err}
	if err != nil {
		var errChain []string
		var errChainTypes []string
		appendErrorChainAttrs(&errChain, &errChainTypes, err)
		attrs = append(attrs,
			"err_type", fmt.Sprintf("%T", err),
			"err_chain", errChain,
			"err_chain_types", errChainTypes,
		)
		if classes := errorDebugClasses(err); len(classes) != 0 {
			attrs = append(attrs, "err_classes", classes)
		}
		var callbackErr *OAuth2CallbackError
		if errors.As(err, &callbackErr) && callbackErr != nil {
			attrs = append(attrs,
				"oauth2_callback_error", true,
				"oauth2_callback_error_code", callbackErr.Code,
				"oauth2_callback_error_description", callbackErr.Description,
				"oauth2_callback_error_uri", callbackErr.URI,
			)
		}
		var retrieveErr *oauth2.RetrieveError
		if errors.As(err, &retrieveErr) && retrieveErr != nil {
			attrs = append(attrs,
				"oauth2_retrieve_error", true,
				"oauth2_retrieve_error_code", retrieveErr.ErrorCode,
				"oauth2_retrieve_error_description", retrieveErr.ErrorDescription,
				"oauth2_retrieve_error_uri", retrieveErr.ErrorURI,
			)
			if retrieveErr.Response != nil {
				attrs = append(attrs,
					"oauth2_response_status", retrieveErr.Response.Status,
					"oauth2_response_status_code", retrieveErr.Response.StatusCode,
				)
			}
			if len(retrieveErr.Body) != 0 {
				body := string(retrieveErr.Body)
				if len(body) > debugErrorBodyLimit {
					body = body[:debugErrorBodyLimit]
					attrs = append(attrs, "oauth2_response_body_truncated", true)
				}
				attrs = append(attrs, "oauth2_response_body", body)
			}
		}
	}
	return
}

func appendErrorChainAttrs(errChain, errChainTypes *[]string, err error) {
	if err != nil {
		*errChain = append(*errChain, err.Error())
		*errChainTypes = append(*errChainTypes, fmt.Sprintf("%T", err))
		appendErrorChainAttrs(errChain, errChainTypes, errors.Unwrap(err))
	}
}

func appendErrorDebugClass(classes []string, err, target error, name string) []string {
	if errors.Is(err, target) {
		classes = append(classes, name)
	}
	return classes
}

func errorDebugClasses(err error) (classes []string) {
	classes = appendErrorDebugClass(classes, err, ErrOAuth2NotConfigured, "oauth2_not_configured")
	classes = appendErrorDebugClass(classes, err, ErrOAuth2MissingSession, "oauth2_missing_session")
	classes = appendErrorDebugClass(classes, err, ErrOAuth2MissingState, "oauth2_missing_state")
	classes = appendErrorDebugClass(classes, err, ErrOAuth2WrongState, "oauth2_wrong_state")
	classes = appendErrorDebugClass(classes, err, ErrOAuth2MissingPKCEVerifier, "oauth2_missing_pkce_verifier")
	classes = appendErrorDebugClass(classes, err, ErrOAuth2Callback, "oauth2_callback")
	classes = appendErrorDebugClass(classes, err, ErrOIDCDiscovery, "oidc_discovery")
	classes = appendErrorDebugClass(classes, err, ErrOIDCProviderMetadata, "oidc_provider_metadata")
	classes = appendErrorDebugClass(classes, err, ErrOIDCMissingIDToken, "oidc_missing_id_token")
	classes = appendErrorDebugClass(classes, err, ErrOIDCInvalidIDToken, "oidc_invalid_id_token")
	classes = appendErrorDebugClass(classes, err, ErrOIDCMissingNonce, "oidc_missing_nonce")
	classes = appendErrorDebugClass(classes, err, ErrOIDCNonceMismatch, "oidc_nonce_mismatch")
	classes = appendErrorDebugClass(classes, err, errOIDCStaleIDToken, "oidc_stale_id_token")
	classes = appendErrorDebugClass(classes, err, errOIDCInvalidExpiry, "oidc_invalid_expiry")
	classes = appendErrorDebugClass(classes, err, errAuthTimerStale, "auth_timer_stale")
	return
}
