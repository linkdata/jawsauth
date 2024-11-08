package jawsauth

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/linkdata/deadlock"
	"github.com/linkdata/jaws"
)

func getOpenIDConfig(baseURL, realm string) (openidcfg map[string]any, err error) {
	openIdConfigURL := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", baseURL, realm)
	var hr *http.Response
	if hr, err = http.Get(openIdConfigURL); err == nil {
		var b []byte
		if b, err = io.ReadAll(hr.Body); err == nil {
			err = json.Unmarshal(b, &openidcfg)
		}
	}
	return
}

type testJar struct {
	cookies []*http.Cookie
}

func (tj *testJar) SetCookies(u *url.URL, cookies []*http.Cookie) {
	tj.cookies = append(tj.cookies, cookies...)
}

func (tj *testJar) Cookies(u *url.URL) []*http.Cookie {
	return tj.cookies
}

func serverHandlerTest(t *testing.T, baseURL, realm, clientID, clientSecret string) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	http.DefaultClient.Jar = &testJar{}

	openidcfg, err := getOpenIDConfig(baseURL, realm)
	if err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	hsrv := httptest.NewServer(mux)
	defer hsrv.Close()

	jw := jaws.New() // create a default JaWS instance
	defer jw.Close() // ensure we clean up
	jw.AddTemplateLookuper(template.Must(template.New("index.html").Parse("<html></html>")))
	jw.Logger = slog.Default() // optionally set the logger to use
	jw.Debug = deadlock.Debug  // optionally set the debug flag
	go jw.Serve()              // start the JaWS processing loop
	mux.Handle("/jaws/", jw)   // ensure the JaWS routes are handled

	cfg := Config{
		RedirectURL:  hsrv.URL + "/oauth2/callback",
		AuthURL:      openidcfg["authorization_endpoint"].(string),
		TokenURL:     openidcfg["token_endpoint"].(string),
		UserInfoURL:  openidcfg["userinfo_endpoint"].(string),
		Scopes:       []string{"openid email"},
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}

	asrv, err := New(jw, &cfg, mux.Handle)
	if err != nil {
		t.Fatal(err)
	}

	mux.Handle("/needauth", asrv.Handler("index.html", nil))
	mux.Handle("/", jw.Handler("index.html", nil))

	initialresp, err := http.Get(hsrv.URL + "/needauth")
	if err != nil {
		t.Fatal(err)
	}

	if initialresp.StatusCode != http.StatusOK {
		t.Fatal(initialresp.Status)
	}

	b, err := io.ReadAll(initialresp.Body)
	if err != nil {
		t.Fatal(err)
	}

	re := regexp.MustCompile(`action="http[^"]+"`)
	p := re.Find(b)
	if p == nil {
		t.Log(string(b))
		t.Fatal("did not find action")
	}
	action := html.UnescapeString(string(p[8 : len(p)-1]))
	params := url.Values{}
	params.Add("username", "testuser")
	params.Add("password", "password123")
	params.Add("credentialId", "")

	postreq, err := http.NewRequestWithContext(ctx, http.MethodPost, action, strings.NewReader(params.Encode()))
	if err != nil {
		t.Fatal(err)
	}

	postreq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, cookie := range initialresp.Cookies() {
		postreq.AddCookie(cookie)
	}
	resp, err := http.DefaultClient.Do(postreq)

	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatal(resp.Status)
	}

	b, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	resphtml := html.UnescapeString(string(b))
	invalidpass := "Invalid username or password."
	if strings.Contains(resphtml, invalidpass) {
		t.Log(resp.Status)
		t.Log(resp.Header)
		t.Log(resphtml)
		t.Fatal(invalidpass)
	}

	resp, err = http.Get(hsrv.URL + "/needauth")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Log(resp.Header)
		t.Fatal(resp.Status)
	}

	resp, err = http.DefaultClient.Get(hsrv.URL + "/oauth2/logout")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Log(resp.Header)
		t.Fatal(resp.Status)
	}
}
