// Package types contains shared data structures used across the application.
package types

import (
	"crypto/rsa"
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// App contains application-wide dependencies.
type App struct {
	// FipRestClient is a Kubernetes client for FloatingIP custom resources.
	FipRestClient client.Client
	// Clientset is a standard Kubernetes clientset.
	Clientset *kubernetes.Clientset
	// DynamicClient is a dynamic Kubernetes client.
	DynamicClient dynamic.Interface
	// Log is the application logger.
	Log *logrus.Logger
	// PrivateKey is the RSA private key for signing JWTs.
	PrivateKey *rsa.PrivateKey
}

// AuthTokenResponse defines the structure for the JWT token response.
type AuthTokenResponse struct {
	// Token is the signed JWT.
	Token string `json:"token"`
	// ExpiresAt is the token's expiration time.
	ExpiresAt time.Time `json:"expires_at"`
}

// FIPRequest defines the structure for a floating IP request.
type FIPRequest struct {
	// ClientSecret is an extra secret for authenticating client requests.
	ClientSecret string `json:"clientsecret"`
	// Cluster is the target cluster for the floating IP.
	Cluster string `json:"cluster"`
	// Project is the project requesting the floating IP.
	Project string `json:"project"`
	// FloatingIPPool is the pool from which to allocate the IP.
	FloatingIPPool string `json:"floatingippool"`
	// Namespace is the namespace of the service to expose.
	ServiceNamespace string `json:"servicenamespace"`
	// Service is the name of the service to expose.
	ServiceName string `json:"servicename"`
	// IPAddress is a specific IP address to request, if desired.
	IPAddress string `json:"ipaddr,omitempty"`
}

// FIPResponse defines the structure for the response to a floating IP request.
type FIPResponse struct {
	// ClientSecret is an extra secret for authenticating client requests.
	ClientSecret string `json:"clientsecret"`
	// Status is the status of the request (e.g., "approved").
	Status string `json:"status"`
	// Message provides additional information about the status.
	Message string `json:"message,omitempty"`
	// Cluster is the target cluster for the floating IP.
	Cluster string `json:"cluster"`
	// Project is the project requesting the floating IP.
	Project string `json:"project"`
	// FloatingIPPool is the pool from which to allocate the IP.
	FloatingIPPool string `json:"floatingippool"`
	// Namespace is the namespace of the service to expose.
	ServiceNamespace string `json:"servicenamespace"`
	// Service is the name of the service to expose.
	ServiceName string `json:"servicename"`
	// IPAddress is the allocated floating IP address.
	IPAddress string `json:"ipaddr"`
	// Subnet is the subnet from which to allocate the IP.
	Subnet string `json:"subnet"`
}

// FIPReleaseRequest defines the structure for a floating IP release request.
type FIPReleaseRequest struct {
	// ClientSecret is an extra secret for authenticating client requests.
	ClientSecret string `json:"clientsecret"`
	// Cluster is the cluster where the floating IP is allocated.
	Cluster string `json:"cluster"`
	// Project is the project that owns the floating IP.
	Project string `json:"project"`
	// FloatingIPPool is the pool from which to allocate the IP.
	FloatingIPPool string `json:"floatingippool"`
	// Namespace is the namespace of the service to expose.
	ServiceNamespace string `json:"servicenamespace"`
	// Service is the name of the service to expose.
	ServiceName string `json:"servicename"`
	// IPAddress is the floating IP address to release.
	IPAddress string `json:"ipaddr"`
}

// FIPReleaseResponse defines the structure for the response to a floating IP release request.
type FIPReleaseResponse struct {
	// Status is the status of the release request (e.g., "released").
	Status string `json:"status"`
	// Message provides additional information about the status.
	Message string `json:"message,omitempty"`
}

// FIPListRequest defines the structure for listing floating IPs for a project.
type FIPListRequest struct {
	// ClientSecret is an extra secret for authenticating client requests.
	ClientSecret string `json:"clientsecret"`
	// Cluster is the target cluster.
	Cluster string `json:"cluster"`
	// Project is the project to list floating IPs for.
	Project string `json:"project"`
	// FloatingIPPool is the pool from which the IPs are allocated.
	FloatingIPPool string `json:"floatingippool"`
}

// FIPListResponse defines the structure for the response to a floating IP list request.
type FIPListResponse struct {
	// ClientSecret is an extra secret for authenticating client requests.
	ClientSecret string `json:"clientsecret"`
	// Cluster is the target cluster.
	Cluster string `json:"cluster"`
	// Project is the project for which floating IPs are listed.
	Project string `json:"project"`
	// FloatingIPs is the list of floating IPs.
	FloatingIPs []FloatingIP `json:"floatingips"`
}

// FloatingIP defines the structure for a single floating IP in the list response.
type FloatingIP struct {
	// Project is the project that owns the floating IP.
	Project string `json:"project"`
	// Cluster is the cluster where the floating IP is allocated.
	Cluster string `json:"cluster"`
	// FloatingIPPool is the pool from which the IP is allocated.
	FloatingIPPool string `json:"floatingippool"`
	// ServiceNamespace is the namespace of the service to expose.
	ServiceNamespace string `json:"servicenamespace"`
	// ServiceName is the name of the service to expose.
	ServiceName string `json:"servicename"`
	// IPAddress is the floating IP address.
	IPAddress string `json:"ipaddr"`
}

// FIPDeleteRequest defines the structure for a floating IP delete request.
type FIPDeleteRequest struct {
	// ClientSecret is an extra secret for authenticating client requests.
	ClientSecret string `json:"clientsecret"`
	// Project is the project that owns the floating IP.
	Project string `json:"project"`
	// IPAddress is the floating IP address to delete.
	IPAddress string `json:"ipaddr"`
}

// FIPDeleteResponse defines the structure for the response to a floating IP delete request.
type FIPDeleteResponse struct {
	// Status is the status of the delete request (e.g., "deleted").
	Status string `json:"status"`
	// Message provides additional information about the status.
	Message string `json:"message,omitempty"`
}
