package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Scope       string `json:"scope,omitempty"`
}

type ErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description,omitempty"`
}

type JWKSResponse struct {
	Keys []JWK `json:"keys"`
}

type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
	Alg string `json:"alg"`
}

const (
	TokenExpireSecs = 60
)

var (
	PORT = 8080

	privateKey *rsa.PrivateKey

	// Simple hardcoded validation for demo purposes
	// In production, validate against a database or external service
	ValidClients = map[string]string{
		"test_client":  "test_secret",
		"demo_client":  "demo_secret",
		"kafka-server": "kafka-server-secret",
	}
)

func init() {
	var err error
	privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal("Failed to generate RSA key:", err)
	}
}

func tokenHandler(w http.ResponseWriter, r *http.Request) {
	// log.Printf("Request URL query: %s", r.URL.RawQuery)
	// buf := new(bytes.Buffer)
	// _, err := buf.ReadFrom(r.Body)
	// if err != nil {
	// 	log.Fatalf("could not read request body: %v", err)
	// }
	// log.Printf("Request Body: %s", buf.String())

	if r.Method != http.MethodPost {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		err := json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Method not allowed",
		})
		if err != nil {
			log.Fatalf("could not encode response: %s", err)
		}
		return
	}

	if err := r.ParseForm(); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		err := json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Failed to parse form data",
		})
		if err != nil {
			log.Fatalf("could not encode response: %s", err)
		}
		return
	}

	clientID, clientSecret := extractAuthCreds(r.Header.Get("Authorization"))

	grantType := r.FormValue("grant_type")
	scope := r.FormValue("scope")

	if grantType != "client_credentials" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		err := json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "unsupported_grant_type",
			ErrorDescription: "Only client_credentials grant type is supported",
		})
		if err != nil {
			log.Fatalf("could not encode response: %s", err)
		}
		return
	}

	if clientID == "" || clientSecret == "" {
		log.Printf("Invalid Request: grant_type = %s, client_id = %s, client_secret = %s, scope = %s",
			grantType, clientID, clientSecret, scope)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		err := json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "Client ID and secret are required",
		})
		if err != nil {
			log.Fatalf("could not encode response: %s", err)
		}
		return
	}

	if !validateClient(clientID, clientSecret) {
		log.Printf("Invalid Request: grant_type = %s, client_id = %s, client_secret = %s, scope = %s",
			grantType, clientID, clientSecret, scope)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		err := json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "invalid_client",
			ErrorDescription: "Invalid client credentials",
		})
		if err != nil {
			log.Fatalf("could not encode response: %s", err)
		}
		return
	}

	// Generate JWT token
	token, err := generateJWTToken(clientID, scope)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		err := json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "server_error",
			ErrorDescription: "Failed to generate token",
		})
		if err != nil {
			log.Fatalf("could not encode response: %s", err)
		}
		return
	}

	log.Printf("Request: grant type = %s, client ID = %s, client secret = %s, scope = %s",
		grantType, clientID, clientSecret, scope)

	response := TokenResponse{
		AccessToken: token,
		TokenType:   "Bearer",
		ExpiresIn:   TokenExpireSecs,
		Scope:       scope,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Fatalf("could not encode token response: %s", err)
	}

	log.Printf("Token Response:  %s", token)
}

func validateClient(clientID, clientSecret string) bool {
	expectedSecret, exists := ValidClients[clientID]
	return exists && expectedSecret == clientSecret
}

func generateJWTToken(clientID, scope string) (string, error) {
	now := time.Now()

	claims := jwt.MapClaims{
		"iss":       "oidc-mock-server",
		"sub":       clientID,
		"aud":       "kafka",
		"exp":       now.Add(time.Duration(TokenExpireSecs) * time.Second).Unix(),
		"iat":       now.Unix(),
		"client_id": clientID,
	}

	if scope != "" {
		claims["scope"] = scope
	}
	log.Printf("Generated token claims: %+v", claims)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	return token.SignedString(privateKey)
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusMethodNotAllowed)
		err := json.NewEncoder(w).Encode(ErrorResponse{
			Error:            "invalid_request",
			ErrorDescription: "Method not allowed",
		})
		if err != nil {
			log.Fatalf("could not encode error response on JWS endpoint: %v", err)
		}
		return
	}

	// Convert RSA public key to JWK format
	publicKey := &privateKey.PublicKey

	// Encode modulus (n) and exponent (e) as base64url
	nBytes := publicKey.N.Bytes()
	n := base64.RawURLEncoding.EncodeToString(nBytes)

	eBytes := big.NewInt(int64(publicKey.E)).Bytes()
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	jwk := JWK{
		Kty: "RSA",
		Use: "sig",
		Kid: "oidc-mock-key-1",
		N:   n,
		E:   e,
		Alg: "RS256",
	}

	response := JWKSResponse{
		Keys: []JWK{jwk},
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	w.WriteHeader(http.StatusOK)
	err := json.NewEncoder(w).Encode(response)
	if err != nil {
		log.Fatalf("could not encode JWKS response: %v", err)
	}
}

func extractAuthCreds(authHdr string) (id, secret string) {
	headerToks := strings.Split(authHdr, " ")

	if len(headerToks) != 2 || headerToks[0] != "Basic" {
		return "", ""
	}

	b64decoder := base64.NewDecoder(base64.StdEncoding, strings.NewReader(headerToks[1]))
	idSecretPair, err := io.ReadAll(b64decoder)
	if err != nil {
		log.Printf("Error decoding Authorization header value: %v", err)
		return "", ""
	}
	creds := strings.Split(string(idSecretPair), ":")
	return creds[0], creds[1]
}

func main() {
	var enableTLS = flag.Bool("tls", false, "Enable TLS/HTTPS")
	var certFile = flag.String("cert", "", "Path to TLS certificate file")
	var keyFile = flag.String("key", "", "Path to TLS private key file")
	var port = flag.Int("port", 8080, "Port to listen on")
	flag.Parse()

	PORT = *port

	idSecrets := []string{}
	for cid, cs := range ValidClients {
		idSecrets = append(idSecrets, fmt.Sprintf("%s/%s", cid, cs))
	}

	http.HandleFunc("/token", tokenHandler)
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)

	if *enableTLS {
		if *certFile == "" {
			log.Fatal("TLS enabled but no certificate file specified. Use --cert=path/to/cert.pem")
		}
		if *keyFile == "" {
			log.Fatal("TLS enabled but no private key file specified. Use --key=path/to/key.pem")
		}

		log.Printf("OIDC Mock Server starting on :%d with TLS", PORT)
		log.Printf("Token endpoint: https://localhost:%d/token", PORT)
		log.Printf("JWKS endpoint: https://localhost:%d/.well-known/jwks.json", PORT)
		log.Printf("Valid clients: %s", strings.Join(idSecrets, ", "))
		log.Printf("Using certificate: %s", *certFile)
		log.Printf("Using private key: %s", *keyFile)

		server := &http.Server{
			Addr:    fmt.Sprintf(":%d", PORT),
			Handler: nil,
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}

		log.Fatal(server.ListenAndServeTLS(*certFile, *keyFile))
	} else {
		log.Printf("OIDC Mock Server starting on :%d", PORT)
		log.Printf("Token endpoint: http://localhost:%d/token", PORT)
		log.Printf("JWKS endpoint: http://localhost:%d/.well-known/jwks.json", PORT)
		log.Printf("Valid clients: %s", strings.Join(idSecrets, ", "))

		log.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", PORT), nil))
	}
}
