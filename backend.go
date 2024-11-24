package main

import (
	"context"
	"fmt"
	"strings"

	secretmanager "cloud.google.com/go/secretmanager/apiv1"
	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"golang.org/x/oauth2"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func listSecrets(ctx context.Context, tokenSource *oauth2.TokenSource, project string) (string, error) {
	smclient, err := secretmanager.NewClient(ctx, option.WithTokenSource(*tokenSource))
	if err != nil {
		return "", fmt.Errorf("secretmanager NewClient: %v", err)
	}
	defer smclient.Close()

	req := &secretmanagerpb.ListSecretsRequest{Parent: "projects/" + project}
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
