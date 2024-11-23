package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

type App struct {
	OauthConfig *oauth2.Config
	CookieJar   *sessions.CookieStore
	SigningKey  ed25519.PrivateKey
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<a href='/oauth2/login'>Login with Google</a>")
}

func (a *App) loginHandler(w http.ResponseWriter, r *http.Request) {
	nonce := genNonce()
	state := callbackState{
		RedirectURL: r.URL.Query().Get("path"),
		Nonce:       nonce,
	}
	stateToken, err := a.encodeCallbackState(state)
	if err != nil {
		http.Error(w, "Failed to encode state: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if err != nil {
		http.Error(w, "Failed to save session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	url := a.OauthConfig.AuthCodeURL(stateToken, oauth2.AccessTypeOffline)
	http.Redirect(w, r, url, http.StatusFound)
}

func (a *App) callbackHandler(w http.ResponseWriter, r *http.Request) {
	stateToken := r.FormValue("state")
	callbackState, err := a.decodeCallbackState(stateToken)
	if err != nil {
		http.Error(w, "Failed to decode state: "+err.Error(), http.StatusInternalServerError)
		return
	}
	code := r.FormValue("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}
	token, err := a.OauthConfig.Exchange(context.Background(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	serializedToken, err := json.Marshal(token)
	if err != nil {
		http.Error(w, "Failed to serialise token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	session, err := a.CookieJar.Get(r, "oauth2-state")
	if err != nil {
		http.Error(w, "Failed to get session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	session.Values["token"] = string(serializedToken)
	err = session.Save(r, w)
	if err != nil {
		http.Error(w, "Failed to save session: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, callbackState.RedirectURL, http.StatusFound)
}

func (a *App) listHandler(w http.ResponseWriter, r *http.Request) {
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
		http.Error(w, "This handler requires authentication which should have been handled by the auth middleware", http.StatusInternalServerError)
		return
	}
	var token *oauth2.Token
	err = json.Unmarshal([]byte(serializedToken), &token)
	if err != nil {
		http.Error(w, "Failed to deserialise token: "+err.Error(), http.StatusInternalServerError)
		return
	}
	tokenSource := a.OauthConfig.TokenSource(context.Background(), token)
	htmlDoc, err := listSecrets(context.Background(), &tokenSource)
	if err != nil {
		http.Error(w, "Failed to access secret: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Write([]byte(htmlDoc))
}

func refreshToken(ctx context.Context, oauthConfig *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) {
	tokenSource := oauthConfig.TokenSource(ctx, token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("Failed to refresh token: %v", err)
	}
	return newToken, nil
}
