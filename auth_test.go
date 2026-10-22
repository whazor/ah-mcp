package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type authTransport func(*http.Request) (*http.Response, error)

func (f authTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestOAuthSitesAndLoginRoutes(t *testing.T) {
	for _, site := range []string{"", " BE "} {
		for _, direct := range []bool{false, true} {
			t.Run(fmt.Sprintf("site=%q/direct=%t", site, direct), func(t *testing.T) {
				t.Setenv("AH_SITE", site)
				t.Setenv("AH_LOGIN_START", fmt.Sprint(direct))
				domain, clientID, application := "nl", "appie-ios", "AHWEBSHOP"
				if site != "" {
					domain, clientID, application = "be", "appie-be-ios", "AHBEWEBSHOP"
				}
				if ahSite() != domain || ahAPIBase() != "https://api.ah."+domain {
					t.Fatal("wrong API site")
				}
				previous := http.DefaultClient
				http.DefaultClient = &http.Client{Transport: authTransport(func(r *http.Request) (*http.Response, error) {
					if r.URL.Host != "api.ah."+domain || r.URL.Path != "/mobile-auth/v1/auth/token" {
						t.Errorf("unexpected token URL: %s", r.URL)
					}
					if r.Header.Get("x-client-name") != clientID || r.Header.Get("x-application") != application {
						t.Errorf("wrong site headers: %v", r.Header)
					}
					body, _ := io.ReadAll(r.Body)
					if !strings.Contains(string(body), clientID) || !strings.Contains(string(body), "test-code") {
						t.Errorf("wrong exchange body: %s", body)
					}
					return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"access_token":"test-access","refresh_token":"test-refresh","expires_in":3600}`))}, nil
				})}
				t.Cleanup(func() { http.DefaultClient = previous })
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				port := listener.Addr().(*net.TCPAddr).Port
				listener.Close()
				origin := fmt.Sprintf("http://127.0.0.1:%d", port)
				tokens := filepath.Join(t.TempDir(), "tokens.json")
				loginURL, done, err := StartOAuthFlow(context.Background(), origin, port, tokens)
				if err != nil {
					t.Fatal(err)
				}
				browser := &http.Client{Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
				// Complete the flow even when a route assertion fails, so its server stops.
				defer func() {
					resp, err := browser.Get(origin + "/callback?code=test-code")
					if err != nil {
						t.Error(err)
						return
					}
					resp.Body.Close()
					select {
					case err := <-done:
						if err != nil {
							t.Error(err)
						}
					case <-time.After(3 * time.Second):
						t.Error("token exchange timed out")
					}
					saved, err := LoadTokens(tokens)
					if err != nil || saved == nil || saved.RefreshToken != "test-refresh" {
						t.Errorf("tokens not saved: %v %v", saved, err)
					}
				}()
				parsed, _ := url.Parse(loginURL)
				if direct {
					if loginURL != origin+"/start" {
						t.Errorf("wrong direct login: %s", loginURL)
					}
				} else if parsed.Path != "/login" || parsed.Query().Get("client_id") != clientID {
					t.Errorf("wrong proxy login: %s", loginURL)
				}
				resp, err := browser.Get(origin + "/start")
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
				target, err := url.Parse(resp.Header.Get("Location"))
				if err != nil {
					t.Fatal(err)
				}
				if resp.StatusCode != http.StatusFound || target.Host != "login.ah."+domain || target.Query().Get("client_id") != clientID || target.Query().Get("redirect_uri") != "appie://login-exit" {
					t.Errorf("wrong login redirect: %d %s", resp.StatusCode, target)
				}
			})
		}
	}
}
