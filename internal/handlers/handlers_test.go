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
	fipv1beta2 "github.com/joeyloman/rancher-fip-manager/pkg/apis/rancher.k8s.binbash.org/v1beta2"
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
	fipv1beta2.AddToScheme(fipScheme)
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

	// Create a FloatingIPPool object (cluster-scoped).
	fipPoolGVR := schema.GroupVersionResource{
		Group:    "rancher.k8s.binbash.org",
		Version:  "v1beta2",
		Resource: "floatingippools",
	}
	fipPool := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "rancher.k8s.binbash.org/v1beta2",
			"kind":       "FloatingIPPool",
			"metadata": map[string]interface{}{
				"name": "test-network",
			},
			"spec": map[string]interface{}{
				"ipConfig": map[string]interface{}{
					"family": "IPv4",
					"subnet": "10.0.0.0/24",
					"pool": map[string]interface{}{
						"start": "10.0.0.1",
						"end":   "10.0.0.254",
					},
				},
			},
		},
	}
	_, err = app.DynamicClient.Resource(fipPoolGVR).Create(ctx, fipPool, metav1.CreateOptions{})
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
		fipList := &fipv1beta2.FloatingIPList{}
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
	fipList := &fipv1beta2.FloatingIPList{}
	err = app.FipRestClient.List(ctx, fipList, &client.ListOptions{Namespace: ns.GetName()})
	require.NoError(t, err)
	assert.Len(t, fipList.Items, 1)

	// check if the labels are removed from the fip object
	fip := fipList.Items[0]
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/cluster-name")
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/service-0-name")
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/service-0-namespace")
}

func TestFIPReleaseWithSingleServiceLabel(t *testing.T) {
	ctx := context.Background()

	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-single-"},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, ns))
	defer app.FipRestClient.Delete(ctx, ns)

	// Create a project object.
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}
	projectName := "test-project-single"
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

	// Create a FloatingIPPool object (cluster-scoped).
	fipPoolGVR := schema.GroupVersionResource{
		Group:    "rancher.k8s.binbash.org",
		Version:  "v1beta2",
		Resource: "floatingippools",
	}
	fipPool := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "rancher.k8s.binbash.org/v1beta2",
			"kind":       "FloatingIPPool",
			"metadata": map[string]interface{}{
				"name": "test-network-single",
			},
			"spec": map[string]interface{}{
				"ipConfig": map[string]interface{}{
					"family": "IPv4",
					"subnet": "10.0.1.0/24",
					"pool": map[string]interface{}{
						"start": "10.0.1.1",
						"end":   "10.0.1.254",
					},
				},
			},
		},
	}
	_, err = app.DynamicClient.Resource(fipPoolGVR).Create(ctx, fipPool, metav1.CreateOptions{})
	require.NoError(t, err)

	// Test FIP Request
	fipRequest := &types.FIPRequest{
		Project:          projectName,
		FloatingIPPool:   "test-network-single",
		ServiceName:      "test-service",
		ServiceNamespace: "default",
		Cluster:          "test-cluster",
		IPAddress:        "10.0.1.1",
	}
	body, err := json.Marshal(fipRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/fip/request", bytes.NewReader(body))
	w := httptest.NewRecorder()

	// Simulate the FIP controller allocating an IP.
	go func() {
		fipList := &fipv1beta2.FloatingIPList{}
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
	fipList := &fipv1beta2.FloatingIPList{}
	err = app.FipRestClient.List(ctx, fipList, &client.ListOptions{Namespace: ns.GetName()})
	require.NoError(t, err)
	assert.Len(t, fipList.Items, 1)

	// With single service label, cluster-name should be removed after release
	fip := fipList.Items[0]
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/cluster-name")
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/service-0-name")
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/service-0-namespace")
}

func TestFIPReleaseWithMultipleServiceLabels(t *testing.T) {
	ctx := context.Background()

	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-multi-"},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, ns))
	defer app.FipRestClient.Delete(ctx, ns)

	// Create a project object.
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}
	projectName := "test-project-multi"
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

	// Create a FloatingIPPool object (cluster-scoped).
	fipPoolGVR := schema.GroupVersionResource{
		Group:    "rancher.k8s.binbash.org",
		Version:  "v1beta2",
		Resource: "floatingippools",
	}
	fipPool := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "rancher.k8s.binbash.org/v1beta2",
			"kind":       "FloatingIPPool",
			"metadata": map[string]interface{}{
				"name": "test-network-multi",
			},
			"spec": map[string]interface{}{
				"ipConfig": map[string]interface{}{
					"family": "IPv4",
					"subnet": "10.0.2.0/24",
					"pool": map[string]interface{}{
						"start": "10.0.2.1",
						"end":   "10.0.2.254",
					},
				},
			},
		},
	}
	_, err = app.DynamicClient.Resource(fipPoolGVR).Create(ctx, fipPool, metav1.CreateOptions{})
	require.NoError(t, err)

	// Test FIP Request for first service
	fipRequest1 := &types.FIPRequest{
		Project:          projectName,
		FloatingIPPool:   "test-network-multi",
		ServiceName:      "test-service-1",
		ServiceNamespace: "default",
		Cluster:          "test-cluster",
		IPAddress:        "10.0.2.1",
	}
	body, err := json.Marshal(fipRequest1)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/fip/request", bytes.NewReader(body))
	w := httptest.NewRecorder()

	// Simulate the FIP controller allocating an IP.
	go func() {
		fipList := &fipv1beta2.FloatingIPList{}
		for {
			err := app.FipRestClient.List(ctx, fipList, &client.ListOptions{Namespace: ns.GetName()})
			if err == nil && len(fipList.Items) > 0 {
				fip := fipList.Items[0]
				fip.Status.IPAddr = fipRequest1.IPAddress
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
	assert.Equal(t, fipRequest1.IPAddress, fipResponse.IPAddress)

	// Test FIP Request for second service (same cluster, same FIP) - should be rejected
	// because the IP already exists and no FloatingIPGroup is specified
	fipRequest2 := &types.FIPRequest{
		Project:          projectName,
		FloatingIPPool:   "test-network-multi",
		ServiceName:      "test-service-2",
		ServiceNamespace: "default",
		Cluster:          "test-cluster",
		IPAddress:        "10.0.2.1",
	}
	body, err = json.Marshal(fipRequest2)
	require.NoError(t, err)

	req = httptest.NewRequest("POST", "/v1/fip/request", bytes.NewReader(body))
	w = httptest.NewRecorder()

	FIPRequestHandler(app)(w, req)

	// Should be rejected because IP already exists and no FloatingIPGroup specified
	assert.Equal(t, http.StatusConflict, w.Code)

	// Verify we still only have one service label (first service)
	fipList := &fipv1beta2.FloatingIPList{}
	err = app.FipRestClient.List(ctx, fipList, &client.ListOptions{Namespace: ns.GetName()})
	require.NoError(t, err)
	assert.Len(t, fipList.Items, 1)

	fip := fipList.Items[0]
	assert.Contains(t, fip.Labels, "rancher.k8s.binbash.org/cluster-name")
	assert.Contains(t, fip.Labels, "rancher.k8s.binbash.org/service-0-name")
	assert.Contains(t, fip.Labels, "rancher.k8s.binbash.org/service-0-namespace")
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/service-1-name")
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/service-1-namespace")

	// Test FIP Release for first service
	fipReleaseRequest := &types.FIPReleaseRequest{
		Project:          projectName,
		ServiceName:      fipRequest1.ServiceName,
		ServiceNamespace: fipRequest1.ServiceNamespace,
		Cluster:          fipRequest1.Cluster,
		FloatingIPPool:   fipRequest1.FloatingIPPool,
		IPAddress:        fipRequest1.IPAddress,
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

	// Verify the FloatingIP was updated - cluster-name should be removed since no services remain
	fipList = &fipv1beta2.FloatingIPList{}
	err = app.FipRestClient.List(ctx, fipList, &client.ListOptions{Namespace: ns.GetName()})
	require.NoError(t, err)
	assert.Len(t, fipList.Items, 1)

	fip = fipList.Items[0]
	// With no service labels left, cluster-name should be removed
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/cluster-name")
	// First service labels should be removed
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/service-0-name")
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/service-0-namespace")
	// Second service labels should NOT exist (request was rejected)
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/service-1-name")
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/service-1-namespace")

}

// TestFIPReleaseWithIPAddressFilter tests that FIPReleaseHandler correctly filters
// by IP address when specified in the release request.
func TestFIPReleaseWithIPAddressFilter(t *testing.T) {
	ctx := context.Background()

	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-ipfilter-"},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, ns))
	defer app.FipRestClient.Delete(ctx, ns)

	// Create a project object.
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}
	projectName := "test-project-ipfilter"
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

	// Create a FloatingIPPool object (cluster-scoped).
	fipPoolGVR := schema.GroupVersionResource{
		Group:    "rancher.k8s.binbash.org",
		Version:  "v1beta2",
		Resource: "floatingippools",
	}
	fipPool := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "rancher.k8s.binbash.org/v1beta2",
			"kind":       "FloatingIPPool",
			"metadata": map[string]interface{}{
				"name": "test-network-ipfilter",
			},
			"spec": map[string]interface{}{
				"ipConfig": map[string]interface{}{
					"family": "IPv4",
					"subnet": "10.0.3.0/24",
					"pool": map[string]interface{}{
						"start": "10.0.3.1",
						"end":   "10.0.3.254",
					},
				},
			},
		},
	}
	_, err = app.DynamicClient.Resource(fipPoolGVR).Create(ctx, fipPool, metav1.CreateOptions{})
	require.NoError(t, err)

	// Test FIP Request
	fipRequest := &types.FIPRequest{
		Project:          projectName,
		FloatingIPPool:   "test-network-ipfilter",
		ServiceName:      "test-service-ipfilter",
		ServiceNamespace: "default",
		Cluster:          "test-cluster",
		IPAddress:        "10.0.3.1",
	}
	body, err := json.Marshal(fipRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/fip/request", bytes.NewReader(body))
	w := httptest.NewRecorder()

	// Simulate the FIP controller allocating an IP.
	go func() {
		fipList := &fipv1beta2.FloatingIPList{}
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

	// Test FIP Release with IP address filter
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
	fipList := &fipv1beta2.FloatingIPList{}
	err = app.FipRestClient.List(ctx, fipList, &client.ListOptions{Namespace: ns.GetName()})
	require.NoError(t, err)
	assert.Len(t, fipList.Items, 1)

	// check if the labels are removed from the fip object
	fip := fipList.Items[0]
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/cluster-name")
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/service-0-name")
	assert.NotContains(t, fip.Labels, "rancher.k8s.binbash.org/service-0-namespace")
}

// TestFIPReleaseWithFloatingIPGroup tests that FIPReleaseHandler correctly filters
// by FloatingIPGroup when specified in the release request.
func TestFIPReleaseWithFloatingIPGroup(t *testing.T) {
	ctx := context.Background()

	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-fipgroup-"},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, ns))
	defer app.FipRestClient.Delete(ctx, ns)

	// Create a project object.
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}
	projectName := "test-project-fipgroup"
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

	// Create a FloatingIPPool object (cluster-scoped).
	fipPoolGVR := schema.GroupVersionResource{
		Group:    "rancher.k8s.binbash.org",
		Version:  "v1beta2",
		Resource: "floatingippools",
	}
	fipPool := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "rancher.k8s.binbash.org/v1beta2",
			"kind":       "FloatingIPPool",
			"metadata": map[string]interface{}{
				"name": "test-network-fipgroup",
			},
			"spec": map[string]interface{}{
				"ipConfig": map[string]interface{}{
					"family": "IPv4",
					"subnet": "10.0.4.0/24",
					"pool": map[string]interface{}{
						"start": "10.0.4.1",
						"end":   "10.0.4.254",
					},
				},
			},
		},
	}
	_, err = app.DynamicClient.Resource(fipPoolGVR).Create(ctx, fipPool, metav1.CreateOptions{})
	require.NoError(t, err)

	// Test FIP Request with FloatingIPGroup - create FIP directly with status to avoid timing issues
	fipRequest := &types.FIPRequest{
		Project:          projectName,
		FloatingIPPool:   "test-network-fipgroup",
		ServiceName:      "test-service-fipgroup",
		ServiceNamespace: "default",
		Cluster:          "test-cluster",
		FloatingIPGroup:  "test-group-1",
		IPAddress:        "10.0.4.1",
	}

	// Create the FIP directly with status to avoid timing issues
	fip := &fipv1beta2.FloatingIP{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "fip-",
			Namespace:    ns.GetName(),
			Labels: map[string]string{
				"rancher.k8s.binbash.org/project-name":        projectName,
				"rancher.k8s.binbash.org/cluster-name":        fipRequest.Cluster,
				"rancher.k8s.binbash.org/service-0-name":      fipRequest.ServiceName,
				"rancher.k8s.binbash.org/service-0-namespace": fipRequest.ServiceNamespace,
				"rancher.k8s.binbash.org/floatingip-group":    fipRequest.FloatingIPGroup,
			},
		},
		Spec: fipv1beta2.FloatingIPSpec{
			IPAddr:         &fipRequest.IPAddress,
			FloatingIPPool: fipRequest.FloatingIPPool,
		},
		Status: fipv1beta2.FloatingIPStatus{
			IPAddr: fipRequest.IPAddress,
		},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, fip))

	// Test FIP Release with FloatingIPGroup filter
	fipReleaseRequest := &types.FIPReleaseRequest{
		Project:          projectName,
		ServiceName:      fipRequest.ServiceName,
		ServiceNamespace: fipRequest.ServiceNamespace,
		Cluster:          fipRequest.Cluster,
		FloatingIPPool:   fipRequest.FloatingIPPool,
		FloatingIPGroup:  "test-group-1",
	}
	body, err := json.Marshal(fipReleaseRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("DELETE", "/v1/fip/release", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FIPReleaseHandler(app)(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var fipReleaseResponse types.FIPReleaseResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &fipReleaseResponse))
	assert.Equal(t, "released", fipReleaseResponse.Status)

	// Verify the FloatingIP was updated.
	fipList := &fipv1beta2.FloatingIPList{}
	err = app.FipRestClient.List(ctx, fipList, &client.ListOptions{Namespace: ns.GetName()})
	require.NoError(t, err)
	assert.Len(t, fipList.Items, 1)

	// check if the labels are removed from the fip object
	fipUpdated := fipList.Items[0]
	assert.NotContains(t, fipUpdated.Labels, "rancher.k8s.binbash.org/cluster-name")
	assert.NotContains(t, fipUpdated.Labels, "rancher.k8s.binbash.org/service-0-name")
	assert.NotContains(t, fipUpdated.Labels, "rancher.k8s.binbash.org/service-0-namespace")
	assert.NotContains(t, fipUpdated.Labels, "rancher.k8s.binbash.org/floatingip-group")
}

// TestFIPReleaseNotFound tests that FIPReleaseHandler returns 404 when no matching FIP is found.
func TestFIPReleaseNotFound(t *testing.T) {
	ctx := context.Background()

	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-notfound-"},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, ns))
	defer app.FipRestClient.Delete(ctx, ns)

	// Create a project object.
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}
	projectName := "test-project-notfound"
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

	// Create a FloatingIPPool object (cluster-scoped).
	fipPoolGVR := schema.GroupVersionResource{
		Group:    "rancher.k8s.binbash.org",
		Version:  "v1beta2",
		Resource: "floatingippools",
	}
	fipPool := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "rancher.k8s.binbash.org/v1beta2",
			"kind":       "FloatingIPPool",
			"metadata": map[string]interface{}{
				"name": "test-network-notfound",
			},
			"spec": map[string]interface{}{
				"ipConfig": map[string]interface{}{
					"family": "IPv4",
					"subnet": "10.0.5.0/24",
					"pool": map[string]interface{}{
						"start": "10.0.5.1",
						"end":   "10.0.5.254",
					},
				},
			},
		},
	}
	_, err = app.DynamicClient.Resource(fipPoolGVR).Create(ctx, fipPool, metav1.CreateOptions{})
	require.NoError(t, err)

	// Test FIP Release for a non-existent service - should return 404
	fipReleaseRequest := &types.FIPReleaseRequest{
		Project:          projectName,
		ServiceName:      "non-existent-service",
		ServiceNamespace: "default",
		Cluster:          "test-cluster",
		FloatingIPPool:   "test-network-notfound",
	}
	body, err := json.Marshal(fipReleaseRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("DELETE", "/v1/fip/release", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FIPReleaseHandler(app)(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestFIPReleaseWithWrongIPAddress tests that FIPReleaseHandler returns 404 when
// the IP address doesn't match any FIP.
func TestFIPReleaseWithWrongIPAddress(t *testing.T) {
	ctx := context.Background()

	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-wrongip-"},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, ns))
	defer app.FipRestClient.Delete(ctx, ns)

	// Create a project object.
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}
	projectName := "test-project-wrongip"
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

	// Create a FloatingIPPool object (cluster-scoped).
	fipPoolGVR := schema.GroupVersionResource{
		Group:    "rancher.k8s.binbash.org",
		Version:  "v1beta2",
		Resource: "floatingippools",
	}
	fipPool := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "rancher.k8s.binbash.org/v1beta2",
			"kind":       "FloatingIPPool",
			"metadata": map[string]interface{}{
				"name": "test-network-wrongip",
			},
			"spec": map[string]interface{}{
				"ipConfig": map[string]interface{}{
					"family": "IPv4",
					"subnet": "10.0.6.0/24",
					"pool": map[string]interface{}{
						"start": "10.0.6.1",
						"end":   "10.0.6.254",
					},
				},
			},
		},
	}
	_, err = app.DynamicClient.Resource(fipPoolGVR).Create(ctx, fipPool, metav1.CreateOptions{})
	require.NoError(t, err)

	// Test FIP Request
	fipRequest := &types.FIPRequest{
		Project:          projectName,
		FloatingIPPool:   "test-network-wrongip",
		ServiceName:      "test-service-wrongip",
		ServiceNamespace: "default",
		Cluster:          "test-cluster",
		IPAddress:        "10.0.6.1",
	}
	body, err := json.Marshal(fipRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/fip/request", bytes.NewReader(body))
	w := httptest.NewRecorder()

	// Simulate the FIP controller allocating an IP.
	go func() {
		fipList := &fipv1beta2.FloatingIPList{}
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

	// Test FIP Release with wrong IP address - should return 404
	fipReleaseRequest := &types.FIPReleaseRequest{
		Project:          projectName,
		ServiceName:      fipRequest.ServiceName,
		ServiceNamespace: fipRequest.ServiceNamespace,
		Cluster:          fipRequest.Cluster,
		FloatingIPPool:   fipRequest.FloatingIPPool,
		IPAddress:        "10.0.6.99", // Wrong IP address
	}
	body, err = json.Marshal(fipReleaseRequest)
	require.NoError(t, err)

	req = httptest.NewRequest("DELETE", "/v1/fip/release", bytes.NewReader(body))
	w = httptest.NewRecorder()

	FIPReleaseHandler(app)(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestFIPReleaseWithWrongFloatingIPGroup tests that FIPReleaseHandler returns 404 when
// the FloatingIPGroup doesn't match any FIP.
func TestFIPReleaseWithWrongFloatingIPGroup(t *testing.T) {
	ctx := context.Background()

	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-wronggroup-"},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, ns))
	defer app.FipRestClient.Delete(ctx, ns)

	// Create a project object.
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}
	projectName := "test-project-wronggroup"
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

	// Create a FloatingIPPool object (cluster-scoped).
	fipPoolGVR := schema.GroupVersionResource{
		Group:    "rancher.k8s.binbash.org",
		Version:  "v1beta2",
		Resource: "floatingippools",
	}
	fipPool := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "rancher.k8s.binbash.org/v1beta2",
			"kind":       "FloatingIPPool",
			"metadata": map[string]interface{}{
				"name": "test-network-wronggroup",
			},
			"spec": map[string]interface{}{
				"ipConfig": map[string]interface{}{
					"family": "IPv4",
					"subnet": "10.0.7.0/24",
					"pool": map[string]interface{}{
						"start": "10.0.7.1",
						"end":   "10.0.7.254",
					},
				},
			},
		},
	}
	_, err = app.DynamicClient.Resource(fipPoolGVR).Create(ctx, fipPool, metav1.CreateOptions{})
	require.NoError(t, err)

	// Test FIP Request with FloatingIPGroup - create FIP directly with status to avoid timing issues
	fipRequest := &types.FIPRequest{
		Project:          projectName,
		FloatingIPPool:   "test-network-wronggroup",
		ServiceName:      "test-service-wronggroup",
		ServiceNamespace: "default",
		Cluster:          "test-cluster",
		FloatingIPGroup:  "test-group-correct",
		IPAddress:        "10.0.7.1",
	}

	// Create the FIP directly with status to avoid timing issues
	fip := &fipv1beta2.FloatingIP{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "fip-",
			Namespace:    ns.GetName(),
			Labels: map[string]string{
				"rancher.k8s.binbash.org/project-name":        projectName,
				"rancher.k8s.binbash.org/cluster-name":        fipRequest.Cluster,
				"rancher.k8s.binbash.org/service-0-name":      fipRequest.ServiceName,
				"rancher.k8s.binbash.org/service-0-namespace": fipRequest.ServiceNamespace,
				"rancher.k8s.binbash.org/floatingip-group":    fipRequest.FloatingIPGroup,
			},
		},
		Spec: fipv1beta2.FloatingIPSpec{
			IPAddr:         &fipRequest.IPAddress,
			FloatingIPPool: fipRequest.FloatingIPPool,
		},
		Status: fipv1beta2.FloatingIPStatus{
			IPAddr: fipRequest.IPAddress,
		},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, fip))

	// Test FIP Release with wrong FloatingIPGroup - should return 404
	fipReleaseRequest := &types.FIPReleaseRequest{
		Project:          projectName,
		ServiceName:      fipRequest.ServiceName,
		ServiceNamespace: fipRequest.ServiceNamespace,
		Cluster:          fipRequest.Cluster,
		FloatingIPPool:   fipRequest.FloatingIPPool,
		FloatingIPGroup:  "test-group-wrong", // Wrong group
	}
	body, err := json.Marshal(fipReleaseRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("DELETE", "/v1/fip/release", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FIPReleaseHandler(app)(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestFIPReleaseWithMultipleServicesAndFloatingIPGroup tests that when releasing a service
// from a FloatingIP that has multiple services sharing the same FloatingIPGroup,
// the floatingip-group label is preserved when other services still use it.
func TestFIPReleaseWithMultipleServicesAndFloatingIPGroup(t *testing.T) {
	ctx := context.Background()

	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-multi-fipgroup-"},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, ns))
	defer app.FipRestClient.Delete(ctx, ns)

	// Create a project object.
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}
	projectName := "test-project-multi-fipgroup"
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

	// Create a FloatingIPPool object (cluster-scoped).
	fipPoolGVR := schema.GroupVersionResource{
		Group:    "rancher.k8s.binbash.org",
		Version:  "v1beta2",
		Resource: "floatingippools",
	}
	fipPool := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "rancher.k8s.binbash.org/v1beta2",
			"kind":       "FloatingIPPool",
			"metadata": map[string]interface{}{
				"name": "test-network-multi-fipgroup",
			},
			"spec": map[string]interface{}{
				"ipConfig": map[string]interface{}{
					"family": "IPv4",
					"subnet": "10.0.5.0/24",
					"pool": map[string]interface{}{
						"start": "10.0.5.1",
						"end":   "10.0.5.254",
					},
				},
			},
		},
	}
	_, err = app.DynamicClient.Resource(fipPoolGVR).Create(ctx, fipPool, metav1.CreateOptions{})
	require.NoError(t, err)

	// Create a FloatingIP with two services sharing the same FloatingIPGroup
	ipAddr := "10.0.5.1"
	fip := &fipv1beta2.FloatingIP{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "fip-",
			Namespace:    ns.GetName(),
			Labels: map[string]string{
				"rancher.k8s.binbash.org/project-name":        projectName,
				"rancher.k8s.binbash.org/cluster-name":        "test-cluster",
				"rancher.k8s.binbash.org/service-0-name":      "test-service-1",
				"rancher.k8s.binbash.org/service-0-namespace": "default",
				"rancher.k8s.binbash.org/service-1-name":      "test-service-2",
				"rancher.k8s.binbash.org/service-1-namespace": "default",
				"rancher.k8s.binbash.org/floatingip-group":    "test-group-1",
			},
		},
		Spec: fipv1beta2.FloatingIPSpec{
			IPAddr:         &ipAddr,
			FloatingIPPool: "test-network-multi-fipgroup",
		},
		Status: fipv1beta2.FloatingIPStatus{
			IPAddr: ipAddr,
		},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, fip))

	// Test FIP Release for first service
	fipReleaseRequest := &types.FIPReleaseRequest{
		Project:          projectName,
		ServiceName:      "test-service-1",
		ServiceNamespace: "default",
		Cluster:          "test-cluster",
		FloatingIPPool:   "test-network-multi-fipgroup",
		IPAddress:        "10.0.5.1",
	}
	body, err := json.Marshal(fipReleaseRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("DELETE", "/v1/fip/release", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FIPReleaseHandler(app)(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var fipReleaseResponse types.FIPReleaseResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &fipReleaseResponse))
	assert.Equal(t, "released", fipReleaseResponse.Status)

	// Verify the FloatingIP was updated - floatingip-group should be preserved
	// since test-service-2 still exists
	fipList := &fipv1beta2.FloatingIPList{}
	err = app.FipRestClient.List(ctx, fipList, &client.ListOptions{Namespace: ns.GetName()})
	require.NoError(t, err)
	assert.Len(t, fipList.Items, 1)

	fipUpdated := fipList.Items[0]
	// First service labels should be removed
	assert.NotContains(t, fipUpdated.Labels, "rancher.k8s.binbash.org/service-0-name")
	assert.NotContains(t, fipUpdated.Labels, "rancher.k8s.binbash.org/service-0-namespace")
	// Second service labels should remain
	assert.Contains(t, fipUpdated.Labels, "rancher.k8s.binbash.org/service-1-name")
	assert.Contains(t, fipUpdated.Labels, "rancher.k8s.binbash.org/service-1-namespace")
	// floatingip-group should be preserved since service-1 still exists
	assert.Contains(t, fipUpdated.Labels, "rancher.k8s.binbash.org/floatingip-group")
	assert.Equal(t, "test-group-1", fipUpdated.Labels["rancher.k8s.binbash.org/floatingip-group"])
	// cluster-name should be preserved since service-1 still exists
	assert.Contains(t, fipUpdated.Labels, "rancher.k8s.binbash.org/cluster-name")
}
