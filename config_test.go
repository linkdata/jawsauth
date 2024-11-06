package jawsauth

import (
	"reflect"
	"testing"

	"golang.org/x/oauth2"
)

func TestConfig_Build(t *testing.T) {
	type fields struct {
		RedirectURL  string
		AuthURL      string
		TokenURL     string
		UserInfoURL  string
		Scopes       []string
		ClientID     string
		ClientSecret string
	}

	stdfields := fields{
		RedirectURL:  "https://application.example.com/oauth2/callback",
		AuthURL:      "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/oauth2/v2.0/authorize",
		TokenURL:     "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000000/oauth2/v2.0/token",
		UserInfoURL:  "https://graph.microsoft.com/v1.0/me?$select=displayName,mail",
		Scopes:       []string{"user.read"},
		ClientID:     "the-client-id",
		ClientSecret: "the-client-secret",
	}

	tests := []struct {
		name          string
		fields        fields
		overrideUrl   string
		wantOauth2cfg *oauth2.Config
		wantErr       bool
	}{
		{
			name:          "empty",
			overrideUrl:   "",
			wantOauth2cfg: nil,
			wantErr:       true,
		},
		{
			name:        "basic",
			fields:      stdfields,
			overrideUrl: "",
			wantOauth2cfg: &oauth2.Config{
				ClientID:     stdfields.ClientID,
				ClientSecret: stdfields.ClientSecret,
				Endpoint: oauth2.Endpoint{
					AuthURL:  stdfields.AuthURL,
					TokenURL: stdfields.TokenURL,
				},
				RedirectURL: stdfields.RedirectURL,
				Scopes:      stdfields.Scopes,
			},
			wantErr: false,
		},
		{
			name:        "override",
			fields:      stdfields,
			overrideUrl: "http://127.0.0.1:8080",
			wantOauth2cfg: &oauth2.Config{
				ClientID:     stdfields.ClientID,
				ClientSecret: stdfields.ClientSecret,
				Endpoint: oauth2.Endpoint{
					AuthURL:  stdfields.AuthURL,
					TokenURL: stdfields.TokenURL,
				},
				RedirectURL: "http://127.0.0.1:8080/oauth2/callback",
				Scopes:      stdfields.Scopes,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{
				RedirectURL:  tt.fields.RedirectURL,
				AuthURL:      tt.fields.AuthURL,
				TokenURL:     tt.fields.TokenURL,
				UserInfoURL:  tt.fields.UserInfoURL,
				Scopes:       tt.fields.Scopes,
				ClientID:     tt.fields.ClientID,
				ClientSecret: tt.fields.ClientSecret,
			}
			gotOauth2cfg, err := cfg.Build(tt.overrideUrl)
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Build() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotOauth2cfg, tt.wantOauth2cfg) {
				t.Errorf("Config.Build() = %v, want %v", gotOauth2cfg, tt.wantOauth2cfg)
			}
		})
	}
}
