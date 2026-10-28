package server

import (
	"crypto/subtle"
	"net/http"

	"github.com/mostlygeek/llama-swap/internal/chain"
	"github.com/mostlygeek/llama-swap/internal/config"
	"github.com/mostlygeek/llama-swap/internal/swaputil"
)

// apiKeyCookieName is the cookie the UI login page stores the API key in so
// that every subsequent browser request - fetches, XHR, and EventSources, all
// of which carry cookies but not all of which can set headers - is
// authenticated.
const apiKeyCookieName = "llamaswap_api_key"

// apiKeyValid reports whether key is one of the configured API keys.
// The comparison is constant-time: the login endpoint turns key checking
// into a guessable oracle, and a short-circuit comparison would let a
// network attacker recover the key byte by byte from response timing.
func apiKeyValid(keys []string, key string) bool {
	if key == "" {
		return false
	}
	for _, k := range keys {
		if subtle.ConstantTimeCompare([]byte(k), []byte(key)) == 1 {
			return true
		}
	}
	return false
}

// extractAPIKey pulls the presented API key from the request: the standard
// headers first, then the UI login cookie.
func extractAPIKey(r *http.Request) string {
	if key := swaputil.ExtractAPIKey(r); key != "" {
		return key
	}
	if cookie, err := r.Cookie(apiKeyCookieName); err == nil {
		return cookie.Value
	}
	return ""
}

// CreateAuthMiddleware returns middleware that validates API keys when the
// config declares any. It accepts the key via Authorization: Bearer,
// Authorization: Basic (password field), x-api-key, or the UI login cookie.
// When no keys are configured the middleware is a pass-through.
func CreateAuthMiddleware(cfg config.Config) chain.Middleware {
	keys := cfg.RequiredAPIKeys
	return func(next http.Handler) http.Handler {
		if len(keys) == 0 {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !apiKeyValid(keys, extractAPIKey(r)) {
				w.Header().Set("WWW-Authenticate", `Basic realm="llama-swap"`)
				swaputil.SendResponse(w, r, http.StatusUnauthorized, "unauthorized: invalid or missing API key")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// CreateRequestContextMiddleware returns middleware that extracts model and
// auth info from the request into the context. Requests where no model can be
// identified are rejected with a 404, and bodies over the size cap with a 413.
//
// JSON and multipart bodies without a Content-Length are first read here, so
// this is where their size cap is usually hit.
func CreateRequestContextMiddleware(cfg config.Config) chain.Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r = markInflightStart(r)
			data, err := swaputil.FetchContext(r, cfg)
			if err != nil {
				if bodyErr := bodyTooLargeFrom(err); bodyErr != nil {
					swaputil.SendResponse(w, r, bodyErr.status, bodyErr.message)
					return
				}
				swaputil.SendError(w, r, swaputil.ErrNoModelInContext)
				return
			}
			_ = data
			next.ServeHTTP(w, r)
		})
	}
}
