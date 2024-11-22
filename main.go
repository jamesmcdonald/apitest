package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

var store *sessions.CookieStore

func main() {
	var client_id string
	var client_secret string
	var cookie_secret string

	for _, s := range []struct {
		name     string
		variable *string
	}{
		{"client_id", &client_id},
		{"client_secret", &client_secret},
		{"cookie_secret", &cookie_secret},
	} {
		f, err := os.Open("/secrets/" + s.name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open %s file: %v\n", s.name, err)
			os.Exit(1)
		}
		data, err := io.ReadAll(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read %s file: %v\n", s.name, err)
			os.Exit(1)
		}
		f.Close()
		*s.variable = strings.TrimSpace(string(data))
	}

	store = sessions.NewCookieStore([]byte(cookie_secret))
	oauthConfig := &oauth2.Config{
		ClientID:     client_id,
		ClientSecret: client_secret,
		RedirectURL:  "https://apitest.jamesmcdonald.com/oauth2/callback",
		Scopes: []string{
			"https://www.googleapis.com/auth/cloud-platform",
		},
		Endpoint: google.Endpoint,
	}

	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/oauth2/login", loginHandler(oauthConfig))
	http.HandleFunc("/oauth2/callback", callbackHandler(oauthConfig))
	http.HandleFunc("/list", listHandler(oauthConfig))
	http.ListenAndServe(":8080", nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<a href='/oauth2/login'>Login with Google</a>")
}

func loginHandler(oauthConfig *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var stateToken string
		const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
		for i := 0; i < 16; i++ {
			rv, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
			if err != nil {
				http.Error(w, "Failed to generate state token: "+err.Error(), http.StatusInternalServerError)
				return
			}
			stateToken += string(chars[rv.Int64()])
		}
		session, err := store.Get(r, "oauth2-state")
		session.Values["stateToken"] = stateToken
		err = session.Save(r, w)
		if err != nil {
			http.Error(w, "Failed to save session: "+err.Error(), http.StatusInternalServerError)
			return
		}
		url := oauthConfig.AuthCodeURL(stateToken, oauth2.AccessTypeOffline)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func callbackHandler(oauthConfig *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "oauth2-state")
		if err != nil {
			http.Error(w, "Failed to get session: "+err.Error(), http.StatusInternalServerError)
			return
		}
		val := session.Values["stateToken"]
		var stateToken string
		if st, ok := val.(string); ok {
			stateToken = st
		} else {
			http.Error(w, "Failed to get state token from session", http.StatusInternalServerError)
			return
		}

		if stateToken != r.FormValue("state") {
			http.Error(w, "State token mismatch", http.StatusBadRequest)
			return
		}
		code := r.FormValue("code")
		if code == "" {
			http.Error(w, "Code not found", http.StatusBadRequest)
			return
		}
		token, err := oauthConfig.Exchange(context.Background(), code)
		if err != nil {
			http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
			return
		}
		session.Values["token"] = *token
		delete(session.Values, "stateToken")
		session.Save(r, w)
		http.Redirect(w, r, "/list", http.StatusTemporaryRedirect)
	}
}

func listHandler(oauthConfig *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, err := store.Get(r, "oauth2-state")
		if err != nil {
			http.Error(w, "Failed to get session: "+err.Error(), http.StatusInternalServerError)
			return
		}
		val := session.Values["token"]
		var token *oauth2.Token
		if t, ok := val.(*oauth2.Token); ok {
			token = t
		} else {
			http.Redirect(w, r, "/oauth2/login", http.StatusTemporaryRedirect)
			return
		}
		tokenSource := oauthConfig.TokenSource(context.Background(), token)
		htmlDoc, err := listSecrets(context.Background(), &tokenSource)
		if err != nil {
			http.Error(w, "Failed to access secret: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.Write([]byte(htmlDoc))
	}
}

func listSecrets(ctx context.Context, tokenSource *oauth2.TokenSource) (string, error) {

	smclient, err := secretmanager.NewClient(ctx, option.WithTokenSource(*tokenSource))
	if err != nil {
		return "", fmt.Errorf("secretmanager NewClient: %v", err)
	}
	defer smclient.Close()

	req := &secretmanagerpb.ListSecretsRequest{Parent: "projects/xanthspod"}
	res := smclient.ListSecrets(ctx, req)
	secrets := []string{}
	for {
		secret, err := res.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return "", fmt.Errorf("secretmanager ListSecrets: %v", err)
		}
		secrets = append(secrets, secret.Name)
	}
	var sb strings.Builder
	sb.WriteString("<!DOCTYPE html><html><head><title>Secrets List</title></head><body><h1>Secrets</h1>")
	sb.WriteString("<ul>")
	for _, secret := range secrets {
		sb.WriteString("<li>")
		sb.WriteString(secret)
	}
	sb.WriteString("</ul>")
	sb.WriteString("</body></html>")
	return sb.String(), nil
}
