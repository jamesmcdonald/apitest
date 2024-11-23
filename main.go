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
