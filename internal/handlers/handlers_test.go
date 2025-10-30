package handlers

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/joeyloman/rancher-fip-api-server/pkg/types"
	fipv1beta1 "github.com/joeyloman/rancher-fip-manager/pkg/apis/rancher.k8s.binbash.org/v1beta1"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

var (
	cfg *rest.Config
	app *types.App
)

func TestMain(m *testing.M) {
	testEnv := &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "..", "test", "crd")},
	}

	var err error
	cfg, err = testEnv.Start()
	if err != nil {
		log.Fatalf("failed to start test environment: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("failed to create clientset: %v", err)
	}

	dynamicClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		log.Fatalf("failed to create dynamic client: %v", err)
	}

	// setup fip rest client
	fipScheme := runtime.NewScheme()
	fipv1beta1.AddToScheme(fipScheme)
	corev1.AddToScheme(fipScheme)
	fipRestClient, err := client.New(cfg, client.Options{Scheme: fipScheme})
	if err != nil {
		log.Fatalf("Error building fip rest client: %s", err.Error())
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("failed to generate private key: %v", err)
	}

	// create the app struct with test config
	app = &types.App{
		Clientset:     clientset,
		DynamicClient: dynamicClient,
		FipRestClient: fipRestClient,
		PrivateKey:    privateKey,
		Log:           logrus.New(),
	}

	code := m.Run()

	err = testEnv.Stop()
	if err != nil {
		log.Printf("failed to stop test environment: %v", err)
	}

	os.Exit(code)
}

func TestFIPLifecycle(t *testing.T) {
	ctx := context.Background()

	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-"},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, ns))
	defer app.FipRestClient.Delete(ctx, ns)

	// Create a project object.
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}
	projectName := "test-project"
	project := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "management.cattle.io/v3",
			"kind":       "Project",
			"metadata": map[string]interface{}{
				"name":      projectName,
				"namespace": ns.GetName(),
			},
		},
	}
	_, err := app.DynamicClient.Resource(gvr).Namespace(ns.GetName()).Create(ctx, project, metav1.CreateOptions{})
	require.NoError(t, err)

	// Test FIP Request
	fipRequest := &types.FIPRequest{
		Project:          projectName,
		FloatingIPPool:   "test-network",
		ServiceName:      "test-service",
		ServiceNamespace: "default",
		Cluster:          "test-cluster",
		IPAddress:        "10.0.0.1",
	}
	body, err := json.Marshal(fipRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/fip/request", bytes.NewReader(body))
	w := httptest.NewRecorder()

	// Simulate the FIP controller allocating an IP.
	go func() {
		fipList := &fipv1beta1.FloatingIPList{}
		for {
			err := app.FipRestClient.List(ctx, fipList, &client.ListOptions{Namespace: ns.GetName()})
			if err == nil && len(fipList.Items) > 0 {
				fip := fipList.Items[0]
				fip.Status.IPAddr = fipRequest.IPAddress
				if err := app.FipRestClient.Status().Update(ctx, &fip); err == nil {
					break
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()

	FIPRequestHandler(app)(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var fipResponse types.FIPResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &fipResponse))
	assert.Equal(t, fipRequest.IPAddress, fipResponse.IPAddress)

	// Test FIP Release
	fipReleaseRequest := &types.FIPReleaseRequest{
		Project:          projectName,
		ServiceName:      fipRequest.ServiceName,
		ServiceNamespace: fipRequest.ServiceNamespace,
		Cluster:          fipRequest.Cluster,
		FloatingIPPool:   fipRequest.FloatingIPPool,
		IPAddress:        fipRequest.IPAddress,
	}
	body, err = json.Marshal(fipReleaseRequest)
	require.NoError(t, err)

	req = httptest.NewRequest("DELETE", "/v1/fip/release", bytes.NewReader(body))
	w = httptest.NewRecorder()

	FIPReleaseHandler(app)(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var fipReleaseResponse types.FIPReleaseResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &fipReleaseResponse))
	assert.Equal(t, "released", fipReleaseResponse.Status)

	// Verify the FloatingIP was updated.
	fipList := &fipv1beta1.FloatingIPList{}
	err = app.FipRestClient.List(ctx, fipList, &client.ListOptions{Namespace: ns.GetName()})
	require.NoError(t, err)
	assert.Len(t, fipList.Items, 1)

	// check if the labels are removed from the fip object
	fip := fipList.Items[0]
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/cluster-name")
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/service-name")
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/service-namespace")
}
