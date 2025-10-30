// Package auth provides functionality for JWT-based authentication and authorization.
package auth

import (
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/joeyloman/rancher-fip-api-server/pkg/types"
	managementv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes"

	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
)

// JWTClaims defines the custom claims for the JWT.
type JWTClaims struct {
	jwt.RegisteredClaims
	// ClientID is the identifier of the client to whom the token was issued.
	ClientID string `json:"client_id"`
}

// GenerateJWT creates and signs a new JWT.
func GenerateJWT(privateKey *rsa.PrivateKey, clientID string, expiration time.Duration) (string, time.Time, error) {
	expiresAt := time.Now().Add(expiration)
	claims := JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		ClientID: clientID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	signedToken, err := token.SignedString(privateKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, expiresAt, nil
}

// ValidateJWT parses and validates a JWT token string.
func ValidateJWT(tokenString string, publicKey *rsa.PublicKey) (*jwt.Token, error) {
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	return token, nil
}

// ValidateClientRequest checks if a client request is authorized by verifying the project and token against a Kubernetes Secret.
func ValidateClientRequest(ctx context.Context, app *types.App, projectRequest string, clientSecretRequest string) bool {
	// // Find the project namespace
	var projects managementv3.ProjectList
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}

	list, err := app.DynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	if err != nil {
		app.Log.Errorf("error gathering cluster list: %s", err.Error())
		return false
	}

	if err = runtime.DefaultUnstructuredConverter.FromUnstructured(list.UnstructuredContent(), &projects); err != nil {
		app.Log.Errorf("error parsing cluster list: %s", err.Error())
		return false
	}

	var project managementv3.Project
	projectFound := false
	for _, p := range projects.Items {
		if p.Name == projectRequest {
			project = p
			projectFound = true
			break
		}
	}

	if !projectFound {
		app.Log.Errorf("project not found: %s", projectRequest)
		return false
	}

	secretName := fmt.Sprintf("rancher-fip-config-%s", project.Name)

	// get the relevant secret
	secret, err := app.Clientset.CoreV1().Secrets(project.Namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		app.Log.Errorf("failed to get secret %s/%s: %v", project.Namespace, secretName, err)
		return false
	}

	projectID, ok := secret.Data["project"]
	if !ok {
		app.Log.Errorf("secret %s/%s does not contain project", project.Namespace, secretName)
		return false
	}

	if string(projectID) != project.Name {
		app.Log.Errorf("projectID does not match projectName")
		return false
	}

	clientSecret, ok := secret.Data["clientSecret"]
	if !ok {
		app.Log.Errorf("secret %s/%s does not contain clientSecret", project.Namespace, secretName)
		return false
	}

	if string(clientSecret) != clientSecretRequest {
		app.Log.Errorf("clientSecret does not match clientSecretRequest")
		return false
	}

	return true
}

// GetPrivateKey fetches and parses a PEM-encoded RSA private key from a Kubernetes Secret.
func GetPrivateKey(ctx context.Context, clientset *kubernetes.Clientset, namespace, secretName, dataKey string) (*rsa.PrivateKey, error) {
	secret, err := clientset.CoreV1().Secrets(namespace).Get(ctx, secretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to get secret %s/%s: %w", namespace, secretName, err)
	}

	privateKeyBytes, ok := secret.Data[dataKey]
	if !ok {
		return nil, fmt.Errorf("secret %s/%s does not contain key %s", namespace, secretName, dataKey)
	}

	privateKey, err := jwt.ParseRSAPrivateKeyFromPEM(privateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key from secret %s/%s: %w", namespace, secretName, err)
	}

	return privateKey, nil
}

// GeneratePrivateKey creates a new RSA private key.
func GeneratePrivateKey() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	return privateKey, nil
}

// SavePrivateKey saves an RSA private key to a Kubernetes Secret.
func SavePrivateKey(ctx context.Context, clientset *kubernetes.Clientset, namespace, secretName string, privateKey *rsa.PrivateKey) error {
	privateKeyBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	secretData := map[string][]byte{
		"key": privateKeyBytes,
	}

	newSecret := &v1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      secretName,
			Namespace: namespace,
		},
		Data: secretData,
	}
	_, err := clientset.CoreV1().Secrets(namespace).Create(ctx, newSecret, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create private key secret %s/%s: %w", namespace, secretName, err)
	}

	return nil
}
