package jawsauth

import "net/http"

type default403handler struct{}

func (default403handler) ServeHTTP(hw http.ResponseWriter, hr *http.Request) {
	hw.WriteHeader(http.StatusForbidden)
	_, _ = hw.Write([]byte(`<html><body><h1>403 Forbidden</h1></body></html>`))
}
