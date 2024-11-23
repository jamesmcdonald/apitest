package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// Probably don't use this key for anything else :D
const testKey = "IL8ZiTot35Hmcza4jTepC96zuLtvfG6flPrntfFT3ypld10h9kMsvyp6DCX9rNoq9x9FOPssT4vI5CmwjXJ4gQ=="

func TestSignToken(t *testing.T) {
	keyData, err := base64.StdEncoding.DecodeString(testKey)
	if err != nil {
		t.Fatalf("error decoding key: %v", err)
	}
	signingKey := ed25519.PrivateKey(keyData)

	// Create a new App with a signing key
	app := App{
		SigningKey: signingKey,
	}

	token := "sometokentexthere"
	expected := "eL-rvBNtYoG9QDzDiLJFM2_wBWSnaFW_3esHZ6FqDgnALW-7paa1kGSvTcuM3zjEFDVVUs08ab5iwgRYoe9SCQ"
	res := app.sign(token)
	if res != expected {
		t.Fatalf("expected %s, got %s", expected, res)
	}
}

func TestEncodeCallbackState(t *testing.T) {
	keyData, err := base64.StdEncoding.DecodeString(testKey)
	if err != nil {
		t.Fatalf("error decoding key: %v", err)
	}
	signingKey := ed25519.PrivateKey(keyData)

	// Create a new App with a signing key
	app := App{
		SigningKey: signingKey,
	}

	callbackState := callbackState{
		RedirectURL: "somedatahere",
		Nonce:       "consistent",
	}

	expected := "eyJyZWRpcmVjdF91cmwiOiJzb21lZGF0YWhlcmUiLCJOb25jZSI6ImNvbnNpc3RlbnQifQ.SpQMnmu-1-A9Mu2FCq7V8-yVVeHvUlitJfGk2ccEe5KLOAZaNIha0uqrs3eXqKPTLMxwq5phTIaAXaGiOosrDg"
	res, err := app.encodeCallbackState(callbackState)
	if err != nil {
		t.Fatalf("error encoding callback state: %v", err)
	}
	if res != expected {
		t.Fatalf("expected %s, got %s", expected, res)
	}
}

func TestDecodeCallbackStateSuccess(t *testing.T) {
	keyData, err := base64.StdEncoding.DecodeString(testKey)
	if err != nil {
		t.Fatalf("error decoding key: %v", err)
	}
	signingKey := ed25519.PrivateKey(keyData)

	// Create a new App with a signing key
	app := App{
		SigningKey: signingKey,
	}

	token := "eyJyZWRpcmVjdF91cmwiOiJzb21lZGF0YWhlcmUiLCJOb25jZSI6ImNvbnNpc3RlbnQifQ.SpQMnmu-1-A9Mu2FCq7V8-yVVeHvUlitJfGk2ccEe5KLOAZaNIha0uqrs3eXqKPTLMxwq5phTIaAXaGiOosrDg"
	expected := callbackState{
		RedirectURL: "somedatahere",
		Nonce:       "consistent",
	}
	res, err := app.decodeCallbackState(token)
	if err != nil {
		t.Fatalf("error decoding callback state: %v", err)
	}
	if res != expected {
		t.Fatalf("expected %v, got %v", expected, res)
	}
}
