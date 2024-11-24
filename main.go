package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func main() {
	genkey := flag.Bool("genkey", false, "Generate and print a new ed25519 private key")
	client_id := flag.String("client-id", "", "OAuth2 client ID")
	client_secret := flag.String("client-secret", "", "OAuth2 client secret")
	cookie_secret := flag.String("cookie-secret", "", "Secret for signing session cookies")
	cookie_key := flag.String("cookie-key", "", "Key for encrypting session cookies")
	signing_key := flag.String("signing-key", "", "Base64 encoded ed25519 private key for signing oauth2 state")
	redirect_url := flag.String("redirect-url", "", "OAuth2 redirect URL for callback")
	gcp_project := flag.String("gcp-project", "", "GCP project ID")
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

	// Look for configuration in parameters, then environment variables, then files
	const secretPath = "/secrets"
	const envPrefix = "APITEST_"
	for _, s := range []struct {
		name     string
		variable *string
		secret   bool // If true, also look for a file in secretPath
	}{
		{"client_id", client_id, true},
		{"client_secret", client_secret, true},
		{"cookie_secret", cookie_secret, true},
		{"cookie_key", cookie_key, true},
		{"signing_key", signing_key, true},
		{"redirect_url", redirect_url, false},
		{"gcp_project", gcp_project, false},
	} {
		if s.variable != nil && *s.variable != "" {
			continue
		}
		ev := os.Getenv(strings.ToUpper(envPrefix + s.name))
		if ev != "" {
			*s.variable = ev
			continue
		}
		if !s.secret {
			fmt.Fprintf(os.Stderr, "Missing required configuration: %s\n", s.name)
			os.Exit(1)
		}
		f, err := os.Open(secretPath + "/" + s.name)
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

	sk, err := base64.StdEncoding.DecodeString(*signing_key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to decode signing key: %v\n", err)
		os.Exit(1)
	}

	app := &App{
		OauthConfig: &oauth2.Config{
			ClientID:     *client_id,
			ClientSecret: *client_secret,
			RedirectURL:  *redirect_url,
			Scopes: []string{
				"https://www.googleapis.com/auth/cloud-platform",
			},
			Endpoint: google.Endpoint,
		},
		CookieJar:  sessions.NewCookieStore([]byte(*cookie_secret), []byte(*cookie_key)),
		SigningKey: sk,
		GCPProject: *gcp_project,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", indexHandler)
	mux.HandleFunc("/oauth2/login", app.loginHandler)
	mux.HandleFunc("/oauth2/callback", app.callbackHandler)
	mux.Handle("/list", app.auth(http.HandlerFunc(app.listHandler)))
	http.ListenAndServe(":8080", mux)
}
