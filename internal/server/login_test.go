package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/mostlygeek/llama-swap/internal/config"
)

// setCookies parses the Set-Cookie header(s) written by a handler.
func setCookies(h http.Header) []*http.Cookie {
	var out []*http.Cookie
	for _, line := range strings.Split(h.Get("Set-Cookie"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if c, err := http.ParseSetCookie(line); err == nil {
			out = append(out, c)
		}
	}
	return out
}

func TestServer_Login(t *testing.T) {
	cfg := config.Config{RequiredAPIKeys: []string{"secret"}}
	s := newTestServerWithConfig(cfg, newStubRouter(nil, ""), newStubRouter(nil, ""))

	doLogin := func(t *testing.T, key string) *httptest.ResponseRecorder {
		t.Helper()
		body, _ := json.Marshal(map[string]string{"api_key": key})
		r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}

	t.Run("valid key sets cookie", func(t *testing.T) {
		w := doLogin(t, "secret")
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		cookies := setCookies(w.Header())
		if len(cookies) != 1 || cookies[0].Name != apiKeyCookieName || cookies[0].Value != "secret" {
			t.Fatalf("cookies = %v, want one %s=secret", cookies, apiKeyCookieName)
		}
		if !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteLaxMode {
			t.Fatalf("cookie flags: HttpOnly=%v SameSite=%v", cookies[0].HttpOnly, cookies[0].SameSite)
		}
	})

	t.Run("invalid key is rejected", func(t *testing.T) {
		w := doLogin(t, "wrong")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
		if len(setCookies(w.Header())) != 0 {
			t.Fatal("unexpected cookie on failed login")
		}
	})

	t.Run("missing key is rejected", func(t *testing.T) {
		w := doLogin(t, "")
		if w.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", w.Code)
		}
	})

	t.Run("oversize body is rejected with 413", func(t *testing.T) {
		big := strings.Repeat("a", loginBodyLimit+1)
		r := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(big))
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("status = %d, want 413", w.Code)
		}
	})

}

func TestServer_Logout(t *testing.T) {
	s := newTestServerWithConfig(config.Config{RequiredAPIKeys: []string{"secret"}},
		newStubRouter(nil, ""), newStubRouter(nil, ""))

	doLogout := func(t *testing.T, cookie *http.Cookie) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}

	t.Run("presents the session cookie", func(t *testing.T) {
		w := doLogout(t, &http.Cookie{Name: apiKeyCookieName, Value: "secret"})
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		cookies := setCookies(w.Header())
		if len(cookies) != 1 || cookies[0].Name != apiKeyCookieName || cookies[0].MaxAge != -1 {
			t.Fatalf("cookies = %v, want %s with MaxAge=-1", cookies, apiKeyCookieName)
		}
	})

	// Browsers honor a Set-Cookie from a response even when the request
	// carried no cookie, and SameSite=Lax keeps the session cookie off
	// cross-site requests - so a hostile page could force a sign-out
	// without presenting the cookie. The response must not clear it.
	t.Run("no cookie clears nothing", func(t *testing.T) {
		w := doLogout(t, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
		if len(setCookies(w.Header())) != 0 {
			t.Fatal("unexpected clearing cookie on cookieless logout")
		}
	})
}

func TestServer_AuthCheck(t *testing.T) {
	newAuthServer := func() *Server {
		return newTestServerWithConfig(config.Config{RequiredAPIKeys: []string{"secret"}},
			newStubRouter(nil, ""), newStubRouter(nil, ""))
	}

	doCheck := func(s *Server, cookie string) (int, authCheckBody) {
		r := httptest.NewRequest(http.MethodGet, "/api/auth-check", nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: apiKeyCookieName, Value: cookie})
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		var body authCheckBody
		if err := json.NewDecoder(w.Body).Decode(&body); err != nil {
			t.Fatalf("decoding auth-check body: %v", err)
		}
		return w.Code, body
	}

	t.Run("no keys configured passes", func(t *testing.T) {
		s := newTestServerWithConfig(config.Config{}, newStubRouter(nil, ""), newStubRouter(nil, ""))
		code, body := doCheck(s, "")
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		if body.Required || !body.Authenticated {
			t.Fatalf("body = %+v, want required=false authenticated=true", body)
		}
	})

	t.Run("missing cookie is 401 and required", func(t *testing.T) {
		code, body := doCheck(newAuthServer(), "")
		if code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want 401", code)
		}
		if !body.Required || body.Authenticated {
			t.Fatalf("body = %+v, want required=true authenticated=false", body)
		}
	})

	t.Run("valid cookie is 200 and required", func(t *testing.T) {
		code, body := doCheck(newAuthServer(), "secret")
		if code != http.StatusOK {
			t.Fatalf("status = %d, want 200", code)
		}
		if !body.Required || !body.Authenticated {
			t.Fatalf("body = %+v, want required=true authenticated=true", body)
		}
	})

	t.Run("header key also accepted", func(t *testing.T) {
		s := newTestServerWithConfig(config.Config{RequiredAPIKeys: []string{"secret"}},
			newStubRouter(nil, ""), newStubRouter(nil, ""))
		r := httptest.NewRequest(http.MethodGet, "/api/auth-check", nil)
		r.Header.Set("x-api-key", "secret")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", w.Code)
		}
	})
}

func TestServer_UIRoutesUnauthenticated(t *testing.T) {
	s := newTestServerWithConfig(config.Config{RequiredAPIKeys: []string{"secret"}},
		newStubRouter(nil, ""), newStubRouter(nil, ""))

	// The SPA document must load without a key: the login page has to be
	// reachable first.
	r := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code == http.StatusUnauthorized {
		t.Fatalf("GET /ui/ = %d, want the document to serve without auth", w.Code)
	}

	// API endpoints still require a key.
	r = httptest.NewRequest(http.MethodGet, "/api/version", nil)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/version = %d, want 401", w.Code)
	}
	// ... and the login cookie satisfies them.
	r = httptest.NewRequest(http.MethodGet, "/api/version", nil)
	r.AddCookie(&http.Cookie{Name: apiKeyCookieName, Value: "secret"})
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("GET /api/version with cookie = %d, want 200", w.Code)
	}
}
