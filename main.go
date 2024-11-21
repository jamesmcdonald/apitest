package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

func main() {
	var client_id string
	var client_secret string
	for _, s := range []struct {
		name     string
		variable *string
	}{
		{"client_id", &client_id},
		{"client_secret", &client_secret},
	} {
		f, err := os.Open("/secrets/" + s.name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to open %s file: %v\n", s.name, err)
			os.Exit(1)
		}
		defer f.Close()
		data, err := io.ReadAll(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to read %s file: %v\n", s.name, err)
			os.Exit(1)
		}
		*s.variable = strings.TrimSpace(string(data))
	}

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
	http.ListenAndServe(":8080", nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<a href='/oauth2/login'>Login with Google</a>")
}

func loginHandler(oauthConfig *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		url := oauthConfig.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	}
}

func callbackHandler(oauthConfig *oauth2.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		client := oauthConfig.Client(context.Background(), token)

		secretName := "projects/xanthspod/secrets/apitest/versions/latest"
		secret, err := accessSecretVersion(context.Background(), token, client, secretName)
		if err != nil {
			http.Error(w, "Failed to access secret: "+err.Error(), http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(w, "Secret: %s", secret)
	}
}

func accessSecretVersion(ctx context.Context, token *oauth2.Token, client *http.Client, name string) (string, error) {
	tokenSource := oauth2.StaticTokenSource(token)

	smclient, err := secretmanager.NewClient(ctx, option.WithTokenSource(tokenSource))
	if err != nil {
		return "", fmt.Errorf("secretmanager NewClient: %v", err)
	}
	defer smclient.Close()

	req := &secretmanagerpb.AccessSecretVersionRequest{
		Name: name,
	}
	res, err := smclient.AccessSecretVersion(ctx, req)
	if err != nil {
		return "", fmt.Errorf("AccessSecretVersion: %v", err)
	}
	return string(res.Payload.Data), nil
}
