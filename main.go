package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
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

type App struct {
	OauthConfig *oauth2.Config
	CookieJar   *sessions.CookieStore
	SigningKey  ed25519.PrivateKey
}

func main() {
	genkey := flag.Bool("genkey", false, "Generate and print a new ed25519 private key")
	flag.Parse()
	if *genkey {
		key, err := genKey()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to generate key: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(key)
		os.Exit(0)
	}

	var client_id string
	var client_secret string
	var cookie_secret string
	var cookie_key string
	var signing_key string

	for _, s := range []struct {
		name     string
		variable *string
	}{
		{"client_id", &client_id},
		{"client_secret", &client_secret},
		{"cookie_secret", &cookie_secret},
		{"cookie_key", &cookie_key},
		{"signing_key", &signing_key},
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

	sk, err := base64.StdEncoding.DecodeString(signing_key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode signing key: %v\n", err)
		os.Exit(1)
	}

	app := &App{
		OauthConfig: &oauth2.Config{
			ClientID:     client_id,
			ClientSecret: client_secret,
			RedirectURL:  "https://apitest.jamesmcdonald.com/oauth2/callback",
			Scopes: []string{
				"https://www.googleapis.com/auth/cloud-platform",
			},
			Endpoint: google.Endpoint,
		},
		CookieJar:  sessions.NewCookieStore([]byte(cookie_secret), []byte(cookie_key)),
		SigningKey: sk,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/oauth2/login", app.loginHandler)
	mux.HandleFunc("/oauth2/callback", app.callbackHandler)
	mux.Handle("/list", app.auth(http.HandlerFunc(app.listHandler)))
	http.ListenAndServe(":8080", mux)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<a href='/oauth2/login'>Login with Google</a>")
}

func genNonce() string {
	const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	var token string
	for i := 0; i < 16; i++ {
		rv, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			return ""
		}
		token += string(chars[rv.Int64()])
	}
	return token
}

// sign signs data with ed25519 using the key from the app
func (a *App) sign(data string) string {
	sig := ed25519.Sign(a.SigningKey, []byte(data))
	return base64.RawURLEncoding.EncodeToString(sig)
}

func genKey() (string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	privString := base64.StdEncoding.EncodeToString(priv)
	return privString, nil
}

type callbackState struct {
	RedirectURL string `json:"redirect_url"`
	Nonce       string
}

func (a *App) encodeCallbackState(state callbackState) (string, error) {
	rawState, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	signature := a.sign(string(rawState))
	stateToken := base64.RawURLEncoding.EncodeToString(rawState) + "." + signature
	return stateToken, nil
}

func (a *App) decodeCallbackState(stateToken string) (callbackState, error) {
	parts := strings.Split(stateToken, ".")
	if len(parts) != 2 {
		return callbackState{}, fmt.Errorf("Invalid state token")
	}
	rawState, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return callbackState{}, err
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return callbackState{}, err
	}
	if !ed25519.Verify(a.SigningKey.Public().(ed25519.PublicKey), rawState, signature) {
		return callbackState{}, fmt.Errorf("Invalid signature")
	}
	var state callbackState
	err = json.Unmarshal(rawState, &state)
	if err != nil {
		return callbackState{}, err
	}
	return state, nil
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
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
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
	http.Redirect(w, r, callbackState.RedirectURL, http.StatusTemporaryRedirect)
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

func refreshToken(ctx context.Context, oauthConfig *oauth2.Config, token *oauth2.Token) (*oauth2.Token, error) {
	tokenSource := oauthConfig.TokenSource(ctx, token)
	newToken, err := tokenSource.Token()
	if err != nil {
		return nil, fmt.Errorf("Failed to refresh token: %v", err)
	}
	return newToken, nil
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
