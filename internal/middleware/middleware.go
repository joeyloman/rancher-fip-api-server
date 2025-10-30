// Package middleware provides HTTP middleware functions for the API.
package middleware

import (
	"context"
	"net/http"
	"strings"

	"bytes"
	"encoding/json"
	"io"

	"golang.org/x/time/rate"

	"github.com/joeyloman/rancher-fip-api-server/internal/auth"
	"github.com/joeyloman/rancher-fip-api-server/internal/errors"
	"github.com/joeyloman/rancher-fip-api-server/pkg/types"
)

type contextKey string

const ClientIDContextKey = contextKey("clientID")

// AuthMiddleware validates the JWT from the Authorization header.
func AuthMiddleware(app *types.App) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				errors.WriteJSONError(w, http.StatusUnauthorized, "Authorization header is required")
				return
			}

			parts := strings.Split(authHeader, " ")
			if len(parts) != 2 || parts[0] != "Bearer" {
				errors.WriteJSONError(w, http.StatusUnauthorized, "Authorization header format must be Bearer {token}")
				return
			}

			tokenString := parts[1]
			token, err := auth.ValidateJWT(tokenString, &app.PrivateKey.PublicKey)
			if err != nil {
				errors.WriteJSONError(w, http.StatusUnauthorized, "Invalid token")
				return
			}

			if !token.Valid {
				errors.WriteJSONError(w, http.StatusUnauthorized, "Invalid token")
				return
			}

			// Add clientID to the context for use in downstream handlers
			claims, ok := token.Claims.(*auth.JWTClaims)
			if !ok {
				errors.WriteJSONError(w, http.StatusUnauthorized, "Invalid token claims")
				return
			}

			ctx := context.WithValue(r.Context(), ClientIDContextKey, claims.ClientID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AuthorizeMiddleware checks if the requested project is authorized for the client.
func AuthorizeMiddleware(app *types.App) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			app.Log.Info("AuthorizeMiddleware called")
			bodyBytes, err := io.ReadAll(r.Body)
			if err != nil {
				errors.WriteJSONError(w, http.StatusInternalServerError, "Failed to read request body")
				return
			}
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

			var req struct {
				Project      string `json:"project"`
				ClientSecret string `json:"clientsecret"`
			}

			if err := json.Unmarshal(bodyBytes, &req); err != nil {
				errors.WriteJSONError(w, http.StatusBadRequest, "Invalid request body")
				return
			}

			if !auth.ValidateClientRequest(r.Context(), app, req.Project, req.ClientSecret) {
				errors.WriteJSONError(w, http.StatusForbidden, "Client not authorized")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimitMiddleware applies rate limiting to incoming requests.
func RateLimitMiddleware(requestsPerSecond float64, burst int) func(http.Handler) http.Handler {
	limiter := rate.NewLimiter(rate.Limit(requestsPerSecond), burst)

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				errors.WriteJSONError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
