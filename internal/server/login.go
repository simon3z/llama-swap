package server

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/mostlygeek/llama-swap/internal/swaputil"
)

// authCheckBody is the /api/auth-check payload: whether a key is required at
// all and whether the presented one (cookie or header) is valid. The status
// code mirrors it (401 when a key is required and missing) so status-only
// clients keep working.
type authCheckBody struct {
	Required      bool `json:"required"`
	Authenticated bool `json:"authenticated"`
}

// Login is how the web UI authenticates: the SPA document itself is served
// without a key, the login page posts a candidate key to /api/login, and the
// server stores a valid key in a session cookie. Every later browser request
// (including EventSources, which cannot set headers) then authenticates
// through that cookie in CreateAuthMiddleware.

// loginBodyLimit is the largest accepted /api/login body: an API key never
// needs more, and the endpoint sits outside the model routes'
// MaxRequestBodyBytes cap.
const loginBodyLimit = 4 << 10

// setAPICookie stores key as the UI login cookie: http-only (the page's JS
// never sees it), same-site (no cross-site request can carry it), and secure
// when the request arrived over TLS. It is a session cookie: closing the
// browser signs the user out.
func setAPICookie(w http.ResponseWriter, key string, r *http.Request) {
	cookie := &http.Cookie{
		Name:     apiKeyCookieName,
		Value:    key,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
		cookie.Secure = true
	}
	http.SetCookie(w, cookie)
}

// handleLogin validates the submitted API key and, when it matches, stores it
// in the session cookie. Unauthenticated on purpose: the login page has to
// be reachable before the user holds any credential.
func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	// The endpoint is registered outside the model routes' body-size
	// middleware, so cap it here: an API key never needs more than this.
	// Read with a limit up front (rather than through a MaxBytesReader)
	// because a stream decoder would stop at the first JSON error and a
	// hostile body could slip past the cap unread.
	raw, err := io.ReadAll(io.LimitReader(r.Body, loginBodyLimit+1))
	if len(raw) > loginBodyLimit {
		swaputil.SendResponse(w, r, http.StatusRequestEntityTooLarge, "request body too large")
		return
	}
	var body struct {
		APIKey string `json:"api_key"`
	}
	if err != nil || json.Unmarshal(raw, &body) != nil || body.APIKey == "" {
		swaputil.SendResponse(w, r, http.StatusUnauthorized, "unauthorized: missing api key")
		return
	}
	if !apiKeyValid(s.cfg.RequiredAPIKeys, body.APIKey) {
		swaputil.SendResponse(w, r, http.StatusUnauthorized, "unauthorized: invalid api key")
		return
	}
	setAPICookie(w, body.APIKey, r)
	swaputil.SendResponse(w, r, http.StatusOK, "ok")
}

// handleLogout clears the login cookie, but only when the request actually
// presents the session cookie. Browsers honor a Set-Cookie from a response
// even when the request carried no cookie, and SameSite=Lax keeps the
// session cookie off cross-site requests - so without this check a hostile
// page could force a visiting user to sign out by posting to /api/logout.
func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if _, err := r.Cookie(apiKeyCookieName); err != nil {
		swaputil.SendResponse(w, r, http.StatusOK, "ok")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     apiKeyCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	swaputil.SendResponse(w, r, http.StatusOK, "ok")
}

// handleAuthCheck tells the UI whether a key is required and whether the
// presented one (cookie or header) is valid: 200 when no keys are configured
// or the presented key is valid, 401 otherwise. The JSON body carries both
// facts separately, because a 200 alone cannot say whether the user is
// logged in or no login exists at all - the UI needs that to decide whether
// to offer a sign-out button.
func (s *Server) handleAuthCheck(w http.ResponseWriter, r *http.Request) {
	required := len(s.cfg.RequiredAPIKeys) > 0
	authenticated := !required || apiKeyValid(s.cfg.RequiredAPIKeys, extractAPIKey(r))
	w.Header().Set("Content-Type", "application/json")
	if !authenticated {
		w.WriteHeader(http.StatusUnauthorized)
	} else {
		w.WriteHeader(http.StatusOK)
	}
	json.NewEncoder(w).Encode(authCheckBody{Required: required, Authenticated: authenticated})
}
