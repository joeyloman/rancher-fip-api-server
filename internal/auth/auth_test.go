package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestJWTAuthentication(t *testing.T) {
	// Generate a new RSA private key for testing.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err, "failed to generate RSA private key")

	publicKey := &privateKey.PublicKey

	const clientID = "test-client"
	const expiration = time.Minute * 15

	// Test case 1: Successful JWT generation and validation.
	t.Run("Successful JWT Generation and Validation", func(t *testing.T) {
		signedToken, _, err := GenerateJWT(privateKey, clientID, expiration)
		require.NoError(t, err, "failed to generate JWT")

		token, err := ValidateJWT(signedToken, publicKey)
		require.NoError(t, err, "failed to validate JWT")

		assert.True(t, token.Valid, "token should be valid")

		claims, ok := token.Claims.(*JWTClaims)
		require.True(t, ok, "failed to parse claims")

		assert.Equal(t, clientID, claims.ClientID, "ClientID should match")
	})

	// Test case 2: Validation of an invalid token.
	t.Run("Validation of an Invalid Token", func(t *testing.T) {
		invalidTokenString := "this.is.an.invalid.token"
		_, err := ValidateJWT(invalidTokenString, publicKey)
		assert.Error(t, err, "validation should fail for an invalid token")
	})

	// Test case 3: Token signed with a different key.
	t.Run("Token Signed with Different Key", func(t *testing.T) {
		// Generate another private key.
		anotherPrivateKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		signedToken, _, err := GenerateJWT(privateKey, clientID, expiration)
		require.NoError(t, err)

		// Try to validate with the wrong public key.
		_, err = ValidateJWT(signedToken, &anotherPrivateKey.PublicKey)
		assert.Error(t, err, "validation should fail for token signed with a different key")
	})

	// Test case 4: Expired token validation.
	t.Run("Expired Token Validation", func(t *testing.T) {
		// Create an already expired token.
		claims := JWTClaims{
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			},
			ClientID: clientID,
		}
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
		signedToken, err := token.SignedString(privateKey)
		require.NoError(t, err)

		_, err = ValidateJWT(signedToken, publicKey)
		assert.Error(t, err, "validation should fail for an expired token")
	})
}
