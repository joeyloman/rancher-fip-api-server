// Package kubebuilder provides utilities for interacting with Kubernetes custom resources.
package kubebuilder

import (
	"context"

	"github.com/joeyloman/rancher-fip-manager/pkg/apis/rancher.k8s.binbash.org/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// NewFipRestClient creates a new REST client for FloatingIP custom resources.
func NewFipRestClient(config *rest.Config, scheme *runtime.Scheme) (*rest.RESTClient, error) {
	crdConfig := *config
	crdConfig.ContentConfig.GroupVersion = &v1beta1.SchemeGroupVersion
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
func WatchFloatingIP(ctx context.Context, cl client.Client, namespace, name string) (string, error) {
	fip := &v1beta1.FloatingIP{}
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		default:
			err := cl.Get(ctx, client.ObjectKey{Namespace: namespace, Name: name}, fip)
			if err != nil {
				// handle error, maybe retry
				continue
			}
			if fip.Status.IPAddr != "" {
				return fip.Status.IPAddr, nil
			}
		}
	}
}
