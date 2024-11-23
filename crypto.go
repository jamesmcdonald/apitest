package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
)

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
