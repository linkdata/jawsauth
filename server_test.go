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

	const indexTemplate = `<html>{{with .Auth}}{{.Email}} {{.IsAdmin}} {{.Data}}{{end}}</html>`

	jw.AddTemplateLookuper(template.Must(template.New("index.html").Parse(indexTemplate)))
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
	var logincount int
	asrv.LoginEvent = func(sess *jaws.Session, hr *http.Request) { logincount++ }
	asrv.LogoutEvent = func(sess *jaws.Session, hr *http.Request) { logincount-- }

	if !asrv.Valid() {
		t.Fatal()
	}

	asrv.Set403Handler(nil)

	mux.Handle("/needauth", asrv.Handler("index.html", nil))
	mux.Handle("/needadmin", asrv.HandlerAdmin("index.html", nil))
	mux.Handle("/", jw.Handler("index.html", nil))

	asrv.Wrap(http.NotFoundHandler())
	asrv.WrapAdmin(http.NotFoundHandler())

	initialresp, err := http.Get(hsrv.URL + "/needauth")
	if err != nil {
		t.Fatal(err)
	}

	if initialresp.StatusCode != http.StatusOK {
		t.Fatal(initialresp.Status)
	}

	if logincount != 0 {
		t.Error(logincount)
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

	if logincount != 1 {
		t.Error(logincount)
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

	if !strings.HasPrefix(resphtml, "<html>testuser@example.com true map[email:testuser@example.com email_verified:false family_name:User given_name:Test name:Test User preferred_username:testuser sub:") {
		t.Fatal(resphtml)
	}

	resp, err = http.Get(hsrv.URL + "/needauth")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Log(resp.Header)
		t.Fatal(resp.Status)
	}

	if logincount != 1 {
		t.Error(logincount)
	}

	resp, err = http.DefaultClient.Get(hsrv.URL + "/oauth2/logout")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Log(resp.Header)
		t.Fatal(resp.Status)
	}

	if logincount != 0 {
		t.Error(logincount)
	}

	if !asrv.IsAdmin("testuser@example.com") {
		t.Error("empty admin list, all should be admins")
	}

	asrv.SetAdmins([]string{"admin@example.com"})

	if asrv.IsAdmin("testuser@example.com") {
		t.Error("testuser was admin")
	}

	if !asrv.IsAdmin("admin@example.com") {
		t.Error("was not admin")
	}

	resp, err = http.Get(hsrv.URL + "/needadmin")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Log(resp.Header)
		t.Fatal(resp.Status)
	}

	asrv.SetAdmins([]string{"Test User <testuser@example.com>", "admin@example.com"})

	admins := strings.Join(asrv.GetAdmins(), ",")
	if admins != "admin@example.com,testuser@example.com" {
		t.Error(admins)
	}

	resp, err = http.Get(hsrv.URL + "/needadmin")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Log(resp.Header)
		t.Fatal(resp.Status)
	}
}
