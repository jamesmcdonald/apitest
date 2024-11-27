package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

// Probably don't use these keys for anything else :D
const testKey = "IL8ZiTot35Hmcza4jTepC96zuLtvfG6flPrntfFT3ypld10h9kMsvyp6DCX9rNoq9x9FOPssT4vI5CmwjXJ4gQ=="
const otherKey = "F6apOGn+TY0Ri6Pa6oT1eb+w3xfqZIYzPSOEpeSYmoZTNHKzyOmS2jjf/JcyEGGbrNMp+TN+prDPuzPz5gs78g=="

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
		nonces:     make(map[string]Nonce),
	}

	token := "eyJyZWRpcmVjdF91cmwiOiJzb21lZGF0YWhlcmUiLCJOb25jZSI6ImNvbnNpc3RlbnQifQ.SpQMnmu-1-A9Mu2FCq7V8-yVVeHvUlitJfGk2ccEe5KLOAZaNIha0uqrs3eXqKPTLMxwq5phTIaAXaGiOosrDg"
	app.addNonce("consistent")
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

func TestDecodeCallbackStateWrongKey(t *testing.T) {
	keyData, err := base64.StdEncoding.DecodeString(otherKey)
	if err != nil {
		t.Fatalf("error decoding key: %v", err)
	}
	signingKey := ed25519.PrivateKey(keyData)

	// Create a new App with a signing key
	app := App{
		SigningKey: signingKey,
		nonces:     make(map[string]Nonce),
	}

	token := "eyJyZWRpcmVjdF91cmwiOiJzb21lZGF0YWhlcmUiLCJOb25jZSI6ImNvbnNpc3RlbnQifQ.SpQMnmu-1-A9Mu2FCq7V8-yVVeHvUlitJfGk2ccEe5KLOAZaNIha0uqrs3eXqKPTLMxwq5phTIaAXaGiOosrDg"
	_, err = app.decodeCallbackState(token)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if err.Error() != "invalid signature" {
		t.Fatalf("expected \"invalid signature\", got \"%v\"", err)
	}
}

func TestDecodeCallbackStateBrokenSignature(t *testing.T) {
	keyData, err := base64.StdEncoding.DecodeString(testKey)
	if err != nil {
		t.Fatalf("error decoding key: %v", err)
	}
	signingKey := ed25519.PrivateKey(keyData)

	// Create a new App with a signing key
	app := App{
		SigningKey: signingKey,
	}

	token := "eyJyZWRpcmVjdF91cmwiOiJzb21lZGF0YWhlcmUiLCJOb25jZSI6ImNvbnNpc3RlbnQifQ.SpQMnmu-1-A9Mu2FCq7V8-yVVeHvUlitJfGk2ccEe5KLOAZaNIha0uqrs3eXqKPTLMxwq5phTIaAXaGiOosrD" // character stripped
	_, err = app.decodeCallbackState(token)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if err.Error() != "illegal base64 data at input byte 84" {
		t.Fatalf("expected \"illegal base64 data at input byte 84\", got \"%v\"", err)
	}
}

func TestDecodeCallbackStateBrokenData(t *testing.T) {
	keyData, err := base64.StdEncoding.DecodeString(testKey)
	if err != nil {
		t.Fatalf("error decoding key: %v", err)
	}
	signingKey := ed25519.PrivateKey(keyData)

	// Create a new App with a signing key
	app := App{
		SigningKey: signingKey,
	}

	token := "eyJyZWRpcmVjdF91cmwiOiJzb21lZGF0YWhlcmUiLCJOb25jZSI6ImNvbnNpc3RlbnQif.SpQMnmu-1-A9Mu2FCq7V8-yVVeHvUlitJfGk2ccEe5KLOAZaNIha0uqrs3eXqKPTLMxwq5phTIaAXaGiOosrDg" // character stripped from state part
	_, err = app.decodeCallbackState(token)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if err.Error() != "illegal base64 data at input byte 68" {
		t.Fatalf("expected \"illegal base64 data at input byte 68\", got \"%v\"", err)
	}
}

func TestDecodeCallbackStateGarbageSignature(t *testing.T) {
	keyData, err := base64.StdEncoding.DecodeString(testKey)
	if err != nil {
		t.Fatalf("error decoding key: %v", err)
	}
	signingKey := ed25519.PrivateKey(keyData)

	// Create a new App with a signing key
	app := App{
		SigningKey: signingKey,
	}

	// sig here is base64 for "poops"
	token := "eyJyZWRpcmVjdF91cmwiOiJzb21lZGF0YWhlcmUiLCJOb25jZSI6ImNvbnNpc3RlbnQifQ.cG9vcHMK"
	_, err = app.decodeCallbackState(token)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if err.Error() != "invalid signature" {
		t.Fatalf("expected \"invalid signature\", got \"%v\"", err)
	}
}

func TestDecodeCallbackStateInvalidToken(t *testing.T) {
	keyData, err := base64.StdEncoding.DecodeString(testKey)
	if err != nil {
		t.Fatalf("error decoding key: %v", err)
	}
	signingKey := ed25519.PrivateKey(keyData)

	// Create a new App with a signing key
	app := App{
		SigningKey: signingKey,
	}

	token := "thisisnotabasetoken"
	_, err = app.decodeCallbackState(token)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if err.Error() != "invalid state token" {
		t.Fatalf("expected \"invalid state token\", got \"%v\"", err)
	}
}

func TestDecodeCallbackStateBadJSONValidSignature(t *testing.T) {
	keyData, err := base64.StdEncoding.DecodeString(testKey)
	if err != nil {
		t.Fatalf("error decoding key: %v", err)
	}
	signingKey := ed25519.PrivateKey(keyData)

	// Create a new App with a signing key
	app := App{
		SigningKey: signingKey,
	}

	data := "thisisnotjson"
	b64data := base64.RawURLEncoding.EncodeToString([]byte(data))
	sig := app.sign(data)
	token := b64data + "." + sig
	_, err = app.decodeCallbackState(token)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if err.Error() != "invalid character 'h' in literal true (expecting 'r')" {
		t.Fatalf("expected \"invalid character 'h' in literal true (expecting 'r')\", got \"%v\"", err)
	}
}
