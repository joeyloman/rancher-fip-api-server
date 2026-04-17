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

// TestFIPRequestWithDifferentClusterName tests that when a FloatingIP is already assigned
// to a cluster, requesting the same IP with a different ClusterName returns StatusConflict.
func TestFIPRequestWithDifferentClusterName(t *testing.T) {
	ctx := context.Background()

	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-diff-cluster-"},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, ns))
	defer app.FipRestClient.Delete(ctx, ns)

	// Create a project object.
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}
	projectName := "test-project-diff-cluster"
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
				"name": "test-network-diff-cluster",
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

	// Create a FloatingIP that is already assigned to "test-cluster"
	ipAddr := "10.0.6.1"
	assignedClusterName := "test-cluster"
	fip := &fipv1beta2.FloatingIP{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "fip-",
			Namespace:    ns.GetName(),
			Labels: map[string]string{
				"rancher.k8s.binbash.org/project-name":        projectName,
				"rancher.k8s.binbash.org/cluster-name":        assignedClusterName,
				"rancher.k8s.binbash.org/service-0-name":      "test-service-1",
				"rancher.k8s.binbash.org/service-0-namespace": "default",
				"rancher.k8s.binbash.org/floatingip-group":    "test-group-1",
			},
		},
		Spec: fipv1beta2.FloatingIPSpec{
			IPAddr:         &ipAddr,
			FloatingIPPool: "test-network-diff-cluster",
		},
		Status: fipv1beta2.FloatingIPStatus{
			IPAddr: ipAddr,
		},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, fip))

	// Update the Status.Assigned field using the status subresource
	// (controller would normally do this, but we need to set it manually for the test)
	fip.Status.Assigned = &fipv1beta2.AssignedInfo{
		ClusterName:     assignedClusterName,
		FloatingIPGroup: "test-group-1",
	}
	err = app.FipRestClient.Status().Update(ctx, fip)
	require.NoError(t, err, "failed to update FIP status")

	// Verify the FIP was created with the correct Status.Assigned
	fipList := &fipv1beta2.FloatingIPList{}
	err = app.FipRestClient.List(ctx, fipList, &client.ListOptions{Namespace: ns.GetName()})
	require.NoError(t, err)
	require.Len(t, fipList.Items, 1)

	createdFIP := fipList.Items[0]
	require.NotNil(t, createdFIP.Status.Assigned, "Status.Assigned should not be nil")
	require.Equal(t, assignedClusterName, createdFIP.Status.Assigned.ClusterName, "ClusterName in Status.Assigned should match")

	// Test FIP Request with a different cluster name - should be rejected
	fipRequest := &types.FIPRequest{
		Project:          projectName,
		FloatingIPPool:   "test-network-diff-cluster",
		ServiceName:      "test-service-2",
		ServiceNamespace: "default",
		Cluster:          "different-cluster",
		IPAddress:        "10.0.6.1",
		FloatingIPGroup:  "test-group-1",
	}
	body, err := json.Marshal(fipRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/fip/request", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FIPRequestHandler(app)(w, req)

	// Should be rejected because ClusterName does not match the assigned ClusterName
	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "FloatingIP is already in use by another cluster")
}

// =============================================================================
// TokenHandler Tests
// =============================================================================

// TestTokenHandlerWithValidClientID tests that TokenHandler returns a valid JWT token.
func TestTokenHandlerWithValidClientID(t *testing.T) {
	tokenRequest := struct {
		ClientID string `json:"clientID"`
	}{
		ClientID: "test-client-id",
	}
	body, err := json.Marshal(tokenRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/token", bytes.NewReader(body))
	w := httptest.NewRecorder()

	TokenHandler(app)(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var tokenResponse types.AuthTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &tokenResponse))
	assert.NotEmpty(t, tokenResponse.Token)
	assert.False(t, tokenResponse.ExpiresAt.IsZero())
}

// TestTokenHandlerWithMissingClientID tests that TokenHandler returns 400 when clientID is missing.
func TestTokenHandlerWithMissingClientID(t *testing.T) {
	tokenRequest := struct {
		ClientID string `json:"clientID"`
	}{
		ClientID: "",
	}
	body, err := json.Marshal(tokenRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/token", bytes.NewReader(body))
	w := httptest.NewRecorder()

	TokenHandler(app)(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "clientID is required")
}

// TestTokenHandlerWithInvalidRequestBody tests that TokenHandler returns 400 for invalid JSON.
func TestTokenHandlerWithInvalidRequestBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/token", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	TokenHandler(app)(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid request body")
}

// =============================================================================
// getNextServiceID Unit Tests
// =============================================================================

// TestGetNextServiceIDWithEmptyLabels tests that getNextServiceID returns "0" for empty labels.
func TestGetNextServiceIDWithEmptyLabels(t *testing.T) {
	labels := map[string]string{}
	result := getNextServiceID(labels)
	assert.Equal(t, "0", result)
}

// TestGetNextServiceIDWithNoServiceLabels tests that getNextServiceID returns "0" when no service labels exist.
func TestGetNextServiceIDWithNoServiceLabels(t *testing.T) {
	labels := map[string]string{
		"app": "test",
	}
	result := getNextServiceID(labels)
	assert.Equal(t, "0", result)
}

// TestGetNextServiceIDWithSingleServiceLabel tests that getNextServiceID returns "1" for single service label.
func TestGetNextServiceIDWithSingleServiceLabel(t *testing.T) {
	labels := map[string]string{
		"rancher.k8s.binbash.org/service-0-name":      "test-service",
		"rancher.k8s.binbash.org/service-0-namespace": "default",
	}
	result := getNextServiceID(labels)
	assert.Equal(t, "1", result)
}

// TestGetNextServiceIDWithMultipleServiceLabels tests that getNextServiceID returns the next available ID.
func TestGetNextServiceIDWithMultipleServiceLabels(t *testing.T) {
	labels := map[string]string{
		"rancher.k8s.binbash.org/service-0-name":      "test-service-1",
		"rancher.k8s.binbash.org/service-0-namespace": "default",
		"rancher.k8s.binbash.org/service-1-name":      "test-service-2",
		"rancher.k8s.binbash.org/service-1-namespace": "default",
		"rancher.k8s.binbash.org/service-2-name":      "test-service-3",
		"rancher.k8s.binbash.org/service-2-namespace": "default",
	}
	result := getNextServiceID(labels)
	assert.Equal(t, "3", result)
}

// TestGetNextServiceIDWithNonSequentialServiceLabels tests that getNextServiceID handles non-sequential IDs.
func TestGetNextServiceIDWithNonSequentialServiceLabels(t *testing.T) {
	labels := map[string]string{
		"rancher.k8s.binbash.org/service-0-name":      "test-service-1",
		"rancher.k8s.binbash.org/service-0-namespace": "default",
		"rancher.k8s.binbash.org/service-2-name":      "test-service-3",
		"rancher.k8s.binbash.org/service-2-namespace": "default",
	}
	result := getNextServiceID(labels)
	assert.Equal(t, "3", result)
}

// =============================================================================
// FIPRequestHandler Error Path Tests
// =============================================================================

// TestFIPRequestHandlerWithProjectNotFound tests that FIPRequestHandler returns 400 when project is not found.
func TestFIPRequestHandlerWithProjectNotFound(t *testing.T) {
	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-project-notfound-"},
	}
	require.NoError(t, app.FipRestClient.Create(context.Background(), ns))
	defer app.FipRestClient.Delete(context.Background(), ns)

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
				"name": "test-network-project-notfound",
			},
			"spec": map[string]interface{}{
				"ipConfig": map[string]interface{}{
					"family": "IPv4",
					"subnet": "10.1.0.0/24",
					"pool": map[string]interface{}{
						"start": "10.1.0.1",
						"end":   "10.1.0.254",
					},
				},
			},
		},
	}
	_, err := app.DynamicClient.Resource(fipPoolGVR).Create(context.Background(), fipPool, metav1.CreateOptions{})
	require.NoError(t, err)

	// Test FIP Request with non-existent project
	fipRequest := &types.FIPRequest{
		Project:          "non-existent-project",
		FloatingIPPool:   "test-network-project-notfound",
		ServiceName:      "test-service",
		ServiceNamespace: "default",
		Cluster:          "test-cluster",
	}
	body, err := json.Marshal(fipRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/fip/request", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FIPRequestHandler(app)(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Project not found")
}

// TestFIPRequestHandlerWithIPAlreadyAssigned tests that FIPRequestHandler returns 409 when IP is already assigned.
func TestFIPRequestHandlerWithIPAlreadyAssigned(t *testing.T) {
	ctx := context.Background()

	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-ip-assigned-"},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, ns))
	defer app.FipRestClient.Delete(ctx, ns)

	// Create a project object.
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}
	projectName := "test-project-ip-assigned"
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
				"name": "test-network-ip-assigned",
			},
			"spec": map[string]interface{}{
				"ipConfig": map[string]interface{}{
					"family": "IPv4",
					"subnet": "10.2.0.0/24",
					"pool": map[string]interface{}{
						"start": "10.2.0.1",
						"end":   "10.2.0.254",
					},
				},
			},
		},
	}
	_, err = app.DynamicClient.Resource(fipPoolGVR).Create(ctx, fipPool, metav1.CreateOptions{})
	require.NoError(t, err)

	// Create a FloatingIP that is already assigned
	ipAddr := "10.2.0.1"
	fip := &fipv1beta2.FloatingIP{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "fip-",
			Namespace:    ns.GetName(),
			Labels: map[string]string{
				"rancher.k8s.binbash.org/project-name":        projectName,
				"rancher.k8s.binbash.org/cluster-name":        "test-cluster",
				"rancher.k8s.binbash.org/service-0-name":      "existing-service",
				"rancher.k8s.binbash.org/service-0-namespace": "default",
			},
		},
		Spec: fipv1beta2.FloatingIPSpec{
			IPAddr:         &ipAddr,
			FloatingIPPool: "test-network-ip-assigned",
		},
		Status: fipv1beta2.FloatingIPStatus{
			IPAddr: ipAddr,
		},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, fip))

	// Update the Status.Assigned field
	fip.Status.Assigned = &fipv1beta2.AssignedInfo{
		ClusterName:     "test-cluster",
		FloatingIPGroup: "test-group",
	}
	err = app.FipRestClient.Status().Update(ctx, fip)
	require.NoError(t, err)

	// Test FIP Request with the same IP (should be rejected because IP is already assigned without FloatingIPGroup)
	fipRequest := &types.FIPRequest{
		Project:          projectName,
		FloatingIPPool:   "test-network-ip-assigned",
		ServiceName:      "test-service",
		ServiceNamespace: "default",
		Cluster:          "test-cluster",
		IPAddress:        "10.2.0.1",
	}
	body, err := json.Marshal(fipRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/fip/request", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FIPRequestHandler(app)(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "IP address already exists and no FloatingIPGroup specified")
}

// TestFIPRequestHandlerWithFloatingIPGroupMismatch tests that FIPRequestHandler returns 409 when FloatingIPGroup doesn't match.
func TestFIPRequestHandlerWithFloatingIPGroupMismatch(t *testing.T) {
	ctx := context.Background()

	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-fipgroup-mismatch-"},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, ns))
	defer app.FipRestClient.Delete(ctx, ns)

	// Create a project object.
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}
	projectName := "test-project-fipgroup-mismatch"
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
				"name": "test-network-fipgroup-mismatch",
			},
			"spec": map[string]interface{}{
				"ipConfig": map[string]interface{}{
					"family": "IPv4",
					"subnet": "10.3.0.0/24",
					"pool": map[string]interface{}{
						"start": "10.3.0.1",
						"end":   "10.3.0.254",
					},
				},
			},
		},
	}
	_, err = app.DynamicClient.Resource(fipPoolGVR).Create(ctx, fipPool, metav1.CreateOptions{})
	require.NoError(t, err)

	// Create a FloatingIP that is already assigned with a different FloatingIPGroup
	ipAddr := "10.3.0.1"
	fip := &fipv1beta2.FloatingIP{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "fip-",
			Namespace:    ns.GetName(),
			Labels: map[string]string{
				"rancher.k8s.binbash.org/project-name":        projectName,
				"rancher.k8s.binbash.org/cluster-name":        "test-cluster",
				"rancher.k8s.binbash.org/service-0-name":      "existing-service",
				"rancher.k8s.binbash.org/service-0-namespace": "default",
				"rancher.k8s.binbash.org/floatingip-group":    "test-group-1",
			},
		},
		Spec: fipv1beta2.FloatingIPSpec{
			IPAddr:         &ipAddr,
			FloatingIPPool: "test-network-fipgroup-mismatch",
		},
		Status: fipv1beta2.FloatingIPStatus{
			IPAddr: ipAddr,
		},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, fip))

	// Update the Status.Assigned field
	fip.Status.Assigned = &fipv1beta2.AssignedInfo{
		ClusterName:     "test-cluster",
		FloatingIPGroup: "test-group-1",
	}
	err = app.FipRestClient.Status().Update(ctx, fip)
	require.NoError(t, err)

	// Test FIP Request with a different FloatingIPGroup (should be rejected)
	fipRequest := &types.FIPRequest{
		Project:          projectName,
		FloatingIPPool:   "test-network-fipgroup-mismatch",
		ServiceName:      "test-service",
		ServiceNamespace: "default",
		Cluster:          "test-cluster",
		IPAddress:        "10.3.0.1",
		FloatingIPGroup:  "test-group-2", // Different group
	}
	body, err := json.Marshal(fipRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/fip/request", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FIPRequestHandler(app)(w, req)

	assert.Equal(t, http.StatusConflict, w.Code)
	assert.Contains(t, w.Body.String(), "FloatingIPGroup does not match")
}

// =============================================================================
// FIPListHandler Tests
// =============================================================================

// TestFIPListHandlerWithValidRequest tests that FIPListHandler returns the list of floating IPs.
func TestFIPListHandlerWithValidRequest(t *testing.T) {
	ctx := context.Background()

	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-list-"},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, ns))
	defer app.FipRestClient.Delete(ctx, ns)

	// Create a project object.
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}
	projectName := "test-project-list"
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
				"name": "test-network-list",
			},
			"spec": map[string]interface{}{
				"ipConfig": map[string]interface{}{
					"family": "IPv4",
					"subnet": "10.4.0.0/24",
					"pool": map[string]interface{}{
						"start": "10.4.0.1",
						"end":   "10.4.0.254",
					},
				},
			},
		},
	}
	_, err = app.DynamicClient.Resource(fipPoolGVR).Create(ctx, fipPool, metav1.CreateOptions{})
	require.NoError(t, err)

	// Create a FloatingIP
	ipAddr := "10.4.0.1"
	fip := &fipv1beta2.FloatingIP{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "fip-",
			Namespace:    ns.GetName(),
			Labels: map[string]string{
				"rancher.k8s.binbash.org/project-name":        projectName,
				"rancher.k8s.binbash.org/cluster-name":        "test-cluster",
				"rancher.k8s.binbash.org/service-0-name":      "test-service",
				"rancher.k8s.binbash.org/service-0-namespace": "default",
			},
		},
		Spec: fipv1beta2.FloatingIPSpec{
			IPAddr:         &ipAddr,
			FloatingIPPool: "test-network-list",
		},
		Status: fipv1beta2.FloatingIPStatus{
			IPAddr: ipAddr,
		},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, fip))

	// Test FIP List
	fipListRequest := &types.FIPListRequest{
		Project:        projectName,
		FloatingIPPool: "test-network-list",
		Cluster:        "test-cluster",
	}
	body, err := json.Marshal(fipListRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/fip/list", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FIPListHandler(app)(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var fipListResponse types.FIPListResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &fipListResponse))
	assert.Equal(t, projectName, fipListResponse.Project)
	assert.Len(t, fipListResponse.FloatingIPs, 1)
	assert.Equal(t, ipAddr, fipListResponse.FloatingIPs[0].IPAddress)
}

// TestFIPListHandlerWithProjectNotFound tests that FIPListHandler returns 400 when project is not found.
func TestFIPListHandlerWithProjectNotFound(t *testing.T) {
	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-list-notfound-"},
	}
	require.NoError(t, app.FipRestClient.Create(context.Background(), ns))
	defer app.FipRestClient.Delete(context.Background(), ns)

	// Test FIP List with non-existent project
	fipListRequest := &types.FIPListRequest{
		Project:        "non-existent-project",
		FloatingIPPool: "test-network-list-notfound",
		Cluster:        "test-cluster",
	}
	body, err := json.Marshal(fipListRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("POST", "/v1/fip/list", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FIPListHandler(app)(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Project not found")
}

// =============================================================================
// FIPDeleteHandler Tests
// =============================================================================

// TestFIPDeleteHandlerWithValidRequest tests that FIPDeleteHandler deletes the floating IP.
func TestFIPDeleteHandlerWithValidRequest(t *testing.T) {
	ctx := context.Background()

	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-delete-"},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, ns))
	defer app.FipRestClient.Delete(ctx, ns)

	// Create a project object.
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}
	projectName := "test-project-delete"
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
				"name": "test-network-delete",
			},
			"spec": map[string]interface{}{
				"ipConfig": map[string]interface{}{
					"family": "IPv4",
					"subnet": "10.5.0.0/24",
					"pool": map[string]interface{}{
						"start": "10.5.0.1",
						"end":   "10.5.0.254",
					},
				},
			},
		},
	}
	_, err = app.DynamicClient.Resource(fipPoolGVR).Create(ctx, fipPool, metav1.CreateOptions{})
	require.NoError(t, err)

	// Create a FloatingIP
	ipAddr := "10.5.0.1"
	fip := &fipv1beta2.FloatingIP{
		ObjectMeta: metav1.ObjectMeta{
			GenerateName: "fip-",
			Namespace:    ns.GetName(),
			Labels: map[string]string{
				"rancher.k8s.binbash.org/project-name":        projectName,
				"rancher.k8s.binbash.org/cluster-name":        "test-cluster",
				"rancher.k8s.binbash.org/service-0-name":      "test-service",
				"rancher.k8s.binbash.org/service-0-namespace": "default",
			},
		},
		Spec: fipv1beta2.FloatingIPSpec{
			IPAddr:         &ipAddr,
			FloatingIPPool: "test-network-delete",
		},
		Status: fipv1beta2.FloatingIPStatus{
			IPAddr: ipAddr,
		},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, fip))

	// Test FIP Delete
	fipDeleteRequest := &types.FIPDeleteRequest{
		Project:   projectName,
		IPAddress: ipAddr,
	}
	body, err := json.Marshal(fipDeleteRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("DELETE", "/v1/fip/delete", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FIPDeleteHandler(app)(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	var fipDeleteResponse types.FIPDeleteResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &fipDeleteResponse))
	assert.Equal(t, "deleted", fipDeleteResponse.Status)

	// Verify the FloatingIP was deleted
	fipList := &fipv1beta2.FloatingIPList{}
	err = app.FipRestClient.List(ctx, fipList, &client.ListOptions{Namespace: ns.GetName()})
	require.NoError(t, err)
	assert.Len(t, fipList.Items, 0)
}

// TestFIPDeleteHandlerWithProjectNotFound tests that FIPDeleteHandler returns 400 when project is not found.
func TestFIPDeleteHandlerWithProjectNotFound(t *testing.T) {
	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-delete-notfound-"},
	}
	require.NoError(t, app.FipRestClient.Create(context.Background(), ns))
	defer app.FipRestClient.Delete(context.Background(), ns)

	// Test FIP Delete with non-existent project
	fipDeleteRequest := &types.FIPDeleteRequest{
		Project:   "non-existent-project",
		IPAddress: "10.5.0.1",
	}
	body, err := json.Marshal(fipDeleteRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("DELETE", "/v1/fip/delete", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FIPDeleteHandler(app)(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Project not found")
}

// TestFIPDeleteHandlerWithIPNotFound tests that FIPDeleteHandler returns 404 when IP address is not found.
func TestFIPDeleteHandlerWithIPNotFound(t *testing.T) {
	ctx := context.Background()

	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-delete-ipnotfound-"},
	}
	require.NoError(t, app.FipRestClient.Create(ctx, ns))
	defer app.FipRestClient.Delete(ctx, ns)

	// Create a project object.
	gvr := schema.GroupVersionResource{
		Group:    "management.cattle.io",
		Version:  "v3",
		Resource: "projects",
	}
	projectName := "test-project-delete-ipnotfound"
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

	// Test FIP Delete with non-existent IP address
	fipDeleteRequest := &types.FIPDeleteRequest{
		Project:   projectName,
		IPAddress: "10.5.0.99",
	}
	body, err := json.Marshal(fipDeleteRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("DELETE", "/v1/fip/delete", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FIPDeleteHandler(app)(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "no floatingip found to delete")
}

// =============================================================================
// FIPReleaseHandler Error Path Tests
// =============================================================================

// TestFIPReleaseHandlerWithProjectNotFound tests that FIPReleaseHandler returns 400 when project is not found.
func TestFIPReleaseHandlerWithProjectNotFound(t *testing.T) {
	// Create a namespace for the test.
	ns := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{GenerateName: "test-release-notfound-"},
	}
	require.NoError(t, app.FipRestClient.Create(context.Background(), ns))
	defer app.FipRestClient.Delete(context.Background(), ns)

	// Test FIP Release with non-existent project
	fipReleaseRequest := &types.FIPReleaseRequest{
		Project:          "non-existent-project",
		ServiceName:      "test-service",
		ServiceNamespace: "default",
		Cluster:          "test-cluster",
	}
	body, err := json.Marshal(fipReleaseRequest)
	require.NoError(t, err)

	req := httptest.NewRequest("DELETE", "/v1/fip/release", bytes.NewReader(body))
	w := httptest.NewRecorder()

	FIPReleaseHandler(app)(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Project not found")
}

// TestFIPRequestHandlerWithInvalidRequestBody tests that FIPRequestHandler returns 400 for invalid JSON.
func TestFIPRequestHandlerWithInvalidRequestBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/fip/request", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	FIPRequestHandler(app)(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid request body")
}

// TestFIPReleaseHandlerWithInvalidRequestBody tests that FIPReleaseHandler returns 400 for invalid JSON.
func TestFIPReleaseHandlerWithInvalidRequestBody(t *testing.T) {
	req := httptest.NewRequest("DELETE", "/v1/fip/release", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	FIPReleaseHandler(app)(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid request body")
}

// TestFIPListHandlerWithInvalidRequestBody tests that FIPListHandler returns 400 for invalid JSON.
func TestFIPListHandlerWithInvalidRequestBody(t *testing.T) {
	req := httptest.NewRequest("POST", "/v1/fip/list", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	FIPListHandler(app)(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid request body")
}

// TestFIPDeleteHandlerWithInvalidRequestBody tests that FIPDeleteHandler returns 400 for invalid JSON.
func TestFIPDeleteHandlerWithInvalidRequestBody(t *testing.T) {
	req := httptest.NewRequest("DELETE", "/v1/fip/delete", bytes.NewReader([]byte("invalid json")))
	w := httptest.NewRecorder()

	FIPDeleteHandler(app)(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid request body")
}
