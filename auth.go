package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
)

// auth is a middleware that checks if the user is authenticated,
// makes sure the token is valid, and refreshes it if necessary.
// If the user is not authenticated, it redirects them to the login page.
// The redirect URL is saved to send them to later.
func (a *App) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, err := a.CookieJar.Get(r, "oauth2-state")
		if err != nil {
			http.Error(w, "Failed to get session: "+err.Error(), http.StatusInternalServerError)
			return
		}
		val := session.Values["token"]
		var serializedToken string
		if t, ok := val.(string); ok {
			serializedToken = t
		} else {
			path := fmt.Sprintf("/oauth2/login?path=%s", r.URL.Path)
			http.Redirect(w, r, path, http.StatusFound)
			return
		}

		var token *oauth2.Token
		err = json.Unmarshal([]byte(serializedToken), &token)
		if err != nil {
			http.Error(w, "Failed to deserialise token: "+err.Error(), http.StatusInternalServerError)
			return
		}

		if !token.Valid() {
			ctx := context.Background()
			token, err = refreshToken(ctx, a.OauthConfig, token)
			if err != nil {
				http.Error(w, "Failed to refresh token: "+err.Error(), http.StatusInternalServerError)
				return
			}
			st, err := json.Marshal(token)
			if err != nil {
				http.Error(w, "Failed to serialise token: "+err.Error(), http.StatusInternalServerError)
				return
			}
			session.Values["token"] = string(st)
			err = session.Save(r, w)
			if err != nil {
				http.Error(w, "Failed to save session: "+err.Error(), http.StatusInternalServerError)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
