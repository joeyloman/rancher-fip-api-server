// Package kubebuilder provides utilities for interacting with Kubernetes custom resources.
package kubebuilder

import (
	"context"
	"time"

	"github.com/joeyloman/rancher-fip-manager/pkg/apis/rancher.k8s.binbash.org/v1beta2"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// floatingIPGroupLabel is the label key used to identify floating IP group requests.
	floatingIPGroupLabel = "rancher.k8s.binbash.org/floatingip-group"
)

// NewFipRestClient creates a new REST client for FloatingIP custom resources.
func NewFipRestClient(config *rest.Config, scheme *runtime.Scheme) (*rest.RESTClient, error) {
	crdConfig := *config
	crdConfig.ContentConfig.GroupVersion = &v1beta2.SchemeGroupVersion
	crdConfig.APIPath = "/apis"
	crdConfig.NegotiatedSerializer = serializer.NewCodecFactory(scheme)
	crdConfig.UserAgent = rest.DefaultKubernetesUserAgent()

	restClient, err := rest.UnversionedRESTClientFor(&crdConfig)
	if err != nil {
		return nil, err
	}

	return restClient, nil
}

// WatchFloatingIP watches a FloatingIP resource until its status contains an IP address.
// It polls the resource instead of using a traditional watch.
// If the floatingIPGroupLabel is set on the FloatingIP, it waits until
// Status.Assigned.FloatingIPGroup is also populated before returning.
func WatchFloatingIP(ctx context.Context, cl client.Client, currentFip *v1beta2.FloatingIP) (*v1beta2.FloatingIP, error) {
	fip := &v1beta2.FloatingIP{}

	// Check if the floating IP group label is set
	waitForFloatingIPGroup := false
	if currentFip.Labels != nil && currentFip.Labels[floatingIPGroupLabel] != "" {
		waitForFloatingIPGroup = true
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			err := cl.Get(ctx, client.ObjectKey{Namespace: currentFip.Namespace, Name: currentFip.Name}, fip)
			if err != nil {
				// handle error, maybe retry
				time.Sleep(100 * time.Millisecond)
				continue
			}

			// Check if IP address is assigned
			if fip.Status.IPAddr != "" {
				// If we need to wait for FloatingIPGroup, check that too
				if waitForFloatingIPGroup {
					if fip.Status.Assigned != nil && fip.Status.Assigned.FloatingIPGroup != "" {
						return fip, nil
					}
					// FloatingIPGroup not yet set, continue waiting
					time.Sleep(100 * time.Millisecond)
					continue
				}
				// No FloatingIPGroup required, return now
				return fip, nil
			}

			// Small delay to avoid tight loop
			time.Sleep(100 * time.Millisecond)
		}
	}
}
