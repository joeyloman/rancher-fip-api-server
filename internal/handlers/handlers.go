// Package handlers implements the HTTP handlers for the API endpoints.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/joeyloman/rancher-fip-api-server/internal/auth"
	"github.com/joeyloman/rancher-fip-api-server/internal/errors"
	"github.com/joeyloman/rancher-fip-api-server/internal/kubebuilder"
	"github.com/joeyloman/rancher-fip-api-server/pkg/types"
	fipv1beta2 "github.com/joeyloman/rancher-fip-manager/pkg/apis/rancher.k8s.binbash.org/v1beta2"
	managementv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// getNextServiceID extracts the next available service ID from existing labels.
// It looks for keys matching the pattern "rancher.k8s.binbash.org/service-<id>-name"
// and returns the next available ID (maxID + 1). If no existing service IDs are found,
// it returns "0".
func getNextServiceID(labels map[string]string) string {
	maxID := -1
	for key := range labels {
		if strings.HasPrefix(key, "rancher.k8s.binbash.org/service-") && strings.HasSuffix(key, "-name") {
			// Extract the ID from the key
			prefix := "rancher.k8s.binbash.org/service-"
			suffix := "-name"
			idStr := strings.TrimPrefix(key, prefix)
			idStr = strings.TrimSuffix(idStr, suffix)
			id, err := strconv.Atoi(idStr)
			if err == nil && id > maxID {
				maxID = id
			}
		}
	}
	if maxID >= 0 {
		return strconv.Itoa(maxID + 1)
	}
	return "0"
}

// TokenHandler handles requests for authentication tokens.
// It generates a JWT signed with the application's private key.
func TokenHandler(app *types.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app.Log.Info("TokenHandler called")

		var request struct {
			ClientID string `json:"clientID"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			errors.WriteJSONError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		// If the clientID is not provided, return an error
		if request.ClientID == "" {
			errors.WriteJSONError(w, http.StatusBadRequest, "clientID is required")
			return
		}

		token, expiresAt, err := auth.GenerateJWT(app.PrivateKey, request.ClientID, 1*time.Hour)
		if err != nil {
			app.Log.Errorf("failed to generate JWT: %s", err.Error())
			errors.WriteJSONError(w, http.StatusInternalServerError, "Failed to generate token")
			return
		}

		response := types.AuthTokenResponse{
			Token:     token,
			ExpiresAt: expiresAt,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(response)
	}
}

// FIPRequestHandler handles requests to allocate a new floating IP.
// It creates a FloatingIP custom resource and waits for it to be reconciled.
func FIPRequestHandler(app *types.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app.Log.Info("FIPRequestHandler called")
		var fipRequest types.FIPRequest
		if err := json.NewDecoder(r.Body).Decode(&fipRequest); err != nil {
			errors.WriteJSONError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		// // Find the project namespace
		var projects managementv3.ProjectList
		gvr := schema.GroupVersionResource{
			Group:    "management.cattle.io",
			Version:  "v3",
			Resource: "projects",
		}

		list, err := app.DynamicClient.Resource(gvr).List(r.Context(), metav1.ListOptions{})
		if err != nil {
			errors.WriteJSONError(w, http.StatusInternalServerError, "Failed to list projects")
			app.Log.Errorf("error gathering cluster list: %s", err.Error())
			return
		}

		if err = runtime.DefaultUnstructuredConverter.FromUnstructured(list.UnstructuredContent(), &projects); err != nil {
			errors.WriteJSONError(w, http.StatusInternalServerError, "Failed to parse projects")
			app.Log.Errorf("error parsing cluster list: %s", err.Error())
			return
		}

		var project managementv3.Project
		projectFound := false
		for _, p := range projects.Items {
			if p.Name == fipRequest.Project {
				project = p
				projectFound = true
				break
			}
		}

		if !projectFound {
			errors.WriteJSONError(w, http.StatusBadRequest, "Project not found")
			app.Log.Errorf("project not found: %s", fipRequest.Project)
			return
		}

		var floatingIP *fipv1beta2.FloatingIP
		if fipRequest.IPAddress != "" {
			// IP address is given in the request

			fipList := &fipv1beta2.FloatingIPList{}
			if err := app.FipRestClient.List(r.Context(), fipList, client.InNamespace(project.Namespace)); err != nil {
				app.Log.Errorf("failed to list floatingips: %s", err.Error())
				errors.WriteJSONError(w, http.StatusInternalServerError, "failed to list existing floating IPs")
				return
			}

			var existingFIP *fipv1beta2.FloatingIP
			for i := range fipList.Items {
				// Check of the FloatingIP belongs to the project and equals the requested IP
				if fipList.Items[i].Labels["rancher.k8s.binbash.org/project-name"] == fipRequest.Project && fipList.Items[i].Spec.IPAddr != nil && *fipList.Items[i].Spec.IPAddr == fipRequest.IPAddress {
					existingFIP = &fipList.Items[i]
					break
				}
			}

			if existingFIP != nil {
				// FIP with requested IP exists within the project
				if existingFIP.Status.Assigned != nil {
					// Check if FloatingIPGroup is set in Status.Assigned
					if existingFIP.Status.Assigned.FloatingIPGroup == "" {
						// IP is already assigned, which is an error condition
						errors.WriteJSONError(w, http.StatusConflict, "IP address is already assigned")
						app.Log.Errorf("requested ip %s is already assigned", fipRequest.IPAddress)
						return
					}
					// FloatingIPGroup exists in Status.Assigned, check if request specifies a FloatingIPGroup
					if fipRequest.FloatingIPGroup != "" {
						// Check if the FloatingIPGroup strings match
						if fipRequest.FloatingIPGroup != existingFIP.Status.Assigned.FloatingIPGroup {
							errors.WriteJSONError(w, http.StatusConflict, "FloatingIPGroup does not match the assigned FloatingIPGroup")
							app.Log.Errorf("requested FloatingIPGroup %s does not match assigned FloatingIPGroup %s", fipRequest.FloatingIPGroup, existingFIP.Status.Assigned.FloatingIPGroup)
							return
						}
					}
					// Check if the existingFIP is already assigned to a different cluster-name
					if existingFIP.Status.Assigned.ClusterName != fipRequest.Cluster {
						errors.WriteJSONError(w, http.StatusConflict, "FloatingIP is already in use by another cluster")
						app.Log.Errorf("requested ClusterName %s does not match assigned ClusterName %s", fipRequest.Cluster, existingFIP.Status.Assigned.ClusterName)
						return
					}
				}

				// If no FloatingIPGroup is specified in the request and the IP already exists, decline the request
				if fipRequest.FloatingIPGroup == "" {
					errors.WriteJSONError(w, http.StatusConflict, "IP address already exists and no FloatingIPGroup specified")
					app.Log.Errorf("requested ip %s already exists and no FloatingIPGroup specified", fipRequest.IPAddress)
					return
				}
				// It exists but is not assigned, so we can use it.
				floatingIP = existingFIP
				if floatingIP.Labels == nil {
					floatingIP.Labels = make(map[string]string)
				}
				floatingIP.Labels["rancher.k8s.binbash.org/project-name"] = project.Name
				floatingIP.Labels["rancher.k8s.binbash.org/cluster-name"] = fipRequest.Cluster

				// Determine the service ID to use
				serviceID := getNextServiceID(floatingIP.Labels)
				floatingIP.Labels["rancher.k8s.binbash.org/service-"+serviceID+"-name"] = fipRequest.ServiceName
				floatingIP.Labels["rancher.k8s.binbash.org/service-"+serviceID+"-namespace"] = fipRequest.ServiceNamespace

				if fipRequest.FloatingIPGroup != "" {
					floatingIP.Labels["rancher.k8s.binbash.org/floatingip-group"] = fipRequest.FloatingIPGroup
				}

				if err := app.FipRestClient.Update(r.Context(), floatingIP); err != nil {
					app.Log.Errorf("failed to update floatingip: %s", err.Error())
					errors.WriteJSONError(w, http.StatusInternalServerError, "failed to update floating IP")
					return
				}
				app.Log.Infof("Updated existing FloatingIP %s/%s with new service labels", floatingIP.Namespace, floatingIP.Name)
			} else {
				// FIP with requested IP does not exist, so create it

				// Note: we allow to have FloatingIPGroups with the same name in different FloatingIPs

				fipLabels := make(map[string]string)
				fipLabels["rancher.k8s.binbash.org/project-name"] = project.Name
				fipLabels["rancher.k8s.binbash.org/cluster-name"] = fipRequest.Cluster
				fipLabels["rancher.k8s.binbash.org/service-0-name"] = fipRequest.ServiceName
				fipLabels["rancher.k8s.binbash.org/service-0-namespace"] = fipRequest.ServiceNamespace
				if fipRequest.FloatingIPGroup != "" {
					fipLabels["rancher.k8s.binbash.org/floatingip-group"] = fipRequest.FloatingIPGroup
				}

				floatingIP = &fipv1beta2.FloatingIP{
					ObjectMeta: metav1.ObjectMeta{
						GenerateName: "fip-",
						Namespace:    project.Namespace,
						Labels:       fipLabels,
					},
					Spec: fipv1beta2.FloatingIPSpec{
						IPAddr:         &fipRequest.IPAddress,
						FloatingIPPool: fipRequest.FloatingIPPool,
					},
				}
				if err := app.FipRestClient.Create(r.Context(), floatingIP); err != nil {
					app.Log.Errorf("failed to create floatingip: %s", err.Error())
					errors.WriteJSONError(w, http.StatusInternalServerError, err.Error())
					return
				}
				app.Log.Infof("Created FloatingIP %s/%s", floatingIP.Namespace, floatingIP.Name)
			}
		} else {
			// IP address is NOT given in the request

			// Check if there are unassigned floatingips in the project, if so use one of them
			fipList := &fipv1beta2.FloatingIPList{}
			if err := app.FipRestClient.List(r.Context(), fipList, client.InNamespace(project.Namespace)); err != nil {
				app.Log.Errorf("failed to list floatingips: %s", err.Error())
				errors.WriteJSONError(w, http.StatusInternalServerError, "failed to list existing floating IPs")
				return
			}

			var existingFIP *fipv1beta2.FloatingIP
			// First check if the fipRequest has a FloatingIPGroup set and search if the group already exists within the project and assigned to the cluster
			for i := range fipList.Items {
				if fipRequest.FloatingIPGroup != "" {
					if fipList.Items[i].Labels["rancher.k8s.binbash.org/project-name"] == fipRequest.Project && fipList.Items[i].Labels["rancher.k8s.binbash.org/cluster-name"] == fipRequest.Cluster && fipList.Items[i].Status.Assigned != nil && fipList.Items[i].Status.Assigned.FloatingIPGroup == fipRequest.FloatingIPGroup {
						// We found a FloatingIPGroup match within the project and assigned to the cluster so we need to use this fip
						existingFIP = &fipList.Items[i]
						break
					}
				}
			}
			// If the existingFIP is not set we can search for an unassigned FloatingIP within the project
			if existingFIP == nil {
				for i := range fipList.Items {
					// Check of the FloatingIP belongs to the project and is not assigned
					if fipList.Items[i].Labels["rancher.k8s.binbash.org/project-name"] == fipRequest.Project && fipList.Items[i].Status.IPAddr != "" && fipList.Items[i].Status.Assigned == nil {
						existingFIP = &fipList.Items[i]
						break
					}
				}
			}

			if existingFIP != nil {
				// There is an existing FloatingIP in the project but it's not assigned, so we can use it.
				floatingIP = existingFIP
				if floatingIP.Labels == nil {
					floatingIP.Labels = make(map[string]string)
				}
				floatingIP.Labels["rancher.k8s.binbash.org/project-name"] = project.Name
				floatingIP.Labels["rancher.k8s.binbash.org/cluster-name"] = fipRequest.Cluster

				// Determine the service ID to use
				serviceID := getNextServiceID(floatingIP.Labels)
				floatingIP.Labels["rancher.k8s.binbash.org/service-"+serviceID+"-name"] = fipRequest.ServiceName
				floatingIP.Labels["rancher.k8s.binbash.org/service-"+serviceID+"-namespace"] = fipRequest.ServiceNamespace

				if fipRequest.FloatingIPGroup != "" {
					floatingIP.Labels["rancher.k8s.binbash.org/floatingip-group"] = fipRequest.FloatingIPGroup
				}

				if err := app.FipRestClient.Update(r.Context(), floatingIP); err != nil {
					app.Log.Errorf("failed to update floatingip: %s", err.Error())
					errors.WriteJSONError(w, http.StatusInternalServerError, "failed to update floating IP")
					return
				}
				app.Log.Infof("Updated existing FloatingIP %s/%s with new service labels", floatingIP.Namespace, floatingIP.Name)
			} else {
				// No IP address requested, create a new one with the first service

				fipLabels := make(map[string]string)
				fipLabels["rancher.k8s.binbash.org/project-name"] = project.Name
				fipLabels["rancher.k8s.binbash.org/cluster-name"] = fipRequest.Cluster
				fipLabels["rancher.k8s.binbash.org/service-0-name"] = fipRequest.ServiceName
				fipLabels["rancher.k8s.binbash.org/service-0-namespace"] = fipRequest.ServiceNamespace
				if fipRequest.FloatingIPGroup != "" {
					fipLabels["rancher.k8s.binbash.org/floatingip-group"] = fipRequest.FloatingIPGroup
				}

				floatingIP = &fipv1beta2.FloatingIP{
					ObjectMeta: metav1.ObjectMeta{
						GenerateName: "fip-",
						Namespace:    project.Namespace,
						Labels:       fipLabels,
					},
					Spec: fipv1beta2.FloatingIPSpec{
						FloatingIPPool: fipRequest.FloatingIPPool,
					},
				}
				if err := app.FipRestClient.Create(r.Context(), floatingIP); err != nil {
					app.Log.Errorf("failed to create floatingip: %s", err.Error())
					errors.WriteJSONError(w, http.StatusInternalServerError, err.Error())
					return
				}
				app.Log.Infof("Created FloatingIP %s/%s", floatingIP.Namespace, floatingIP.Name)
			}
		}

		// Watch for the IP address to be allocated
		ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
		defer cancel()

		finalFip, err := kubebuilder.WatchFloatingIP(ctx, app.FipRestClient, floatingIP)
		if err != nil {
			app.Log.Errorf("error watching floating ip: %s", err.Error())

			// Clean up the FloatingIP resource on timeout
			if ctx.Err() == context.DeadlineExceeded {
				err := app.FipRestClient.Delete(context.Background(), floatingIP)
				if err != nil {
					app.Log.Errorf("failed to delete floatingip after timeout: %s", err.Error())
				} else {
					app.Log.Infof("Deleted FloatingIP %s/%s after timeout", floatingIP.Namespace, floatingIP.Name)
				}
				errors.WriteJSONError(w, http.StatusGatewayTimeout, "timeout waiting for IP allocation")
				return
			}

			errors.WriteJSONError(w, http.StatusInternalServerError, "failed to get ip address")
			return
		}

		// Get the subnet from the floating IP pool
		fipPool := fipv1beta2.FloatingIPPool{}
		if err := app.FipRestClient.Get(r.Context(), client.ObjectKey{Name: fipRequest.FloatingIPPool}, &fipPool); err != nil {
			app.Log.Errorf("failed to get floatingippool subnet: %s", err.Error())
			errors.WriteJSONError(w, http.StatusInternalServerError, "failed to get floatingippool subnet")
			return
		}

		var fipGroup, sharedKey string
		if finalFip.Status.Assigned != nil {
			fipGroup = finalFip.Status.Assigned.FloatingIPGroup
			sharedKey = finalFip.Status.Assigned.SharedKey
		}

		fipResponse := types.FIPResponse{
			Status:           "approved",
			ClientSecret:     fipRequest.ClientSecret,
			Cluster:          fipRequest.Cluster,
			Project:          fipRequest.Project,
			FloatingIPPool:   fipRequest.FloatingIPPool,
			ServiceNamespace: fipRequest.ServiceNamespace,
			ServiceName:      fipRequest.ServiceName,
			IPAddress:        finalFip.Status.IPAddr,
			Subnet:           fipPool.Spec.IPConfig.Subnet,
			FloatingIPGroup:  fipGroup,
			SharedKey:        sharedKey,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(fipResponse)
	}
}

// FIPReleaseHandler handles requests to release a floating IP.
// It finds and deletes the corresponding FloatingIP custom resource.
func FIPReleaseHandler(app *types.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app.Log.Info("FIPReleaseHandler called")
		var fipReleaseRequest types.FIPReleaseRequest
		if err := json.NewDecoder(r.Body).Decode(&fipReleaseRequest); err != nil {
			errors.WriteJSONError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		// Find the project namespace
		var projects managementv3.ProjectList
		gvr := schema.GroupVersionResource{
			Group:    "management.cattle.io",
			Version:  "v3",
			Resource: "projects",
		}

		list, err := app.DynamicClient.Resource(gvr).List(r.Context(), metav1.ListOptions{})
		if err != nil {
			errors.WriteJSONError(w, http.StatusInternalServerError, "Failed to list projects")
			app.Log.Errorf("error gathering cluster list: %s", err.Error())
			return
		}

		if err = runtime.DefaultUnstructuredConverter.FromUnstructured(list.UnstructuredContent(), &projects); err != nil {
			errors.WriteJSONError(w, http.StatusInternalServerError, "Failed to parse projects")
			app.Log.Errorf("error parsing cluster list: %s", err.Error())
			return
		}

		var project managementv3.Project
		projectFound := false
		for _, p := range projects.Items {
			if p.Name == fipReleaseRequest.Project {
				project = p
				projectFound = true
				break
			}
		}

		if !projectFound {
			errors.WriteJSONError(w, http.StatusBadRequest, "Project not found")
			app.Log.Errorf("project not found: %s", fipReleaseRequest.Project)
			return
		}

		// List floating IPs with a label selector for project and service
		fipList := &fipv1beta2.FloatingIPList{}
		err = app.FipRestClient.List(r.Context(), fipList, client.InNamespace(project.Namespace), client.MatchingLabels{
			"rancher.k8s.binbash.org/project-name": fipReleaseRequest.Project,
			"rancher.k8s.binbash.org/cluster-name": fipReleaseRequest.Cluster,
		})
		if err != nil {
			app.Log.Errorf("failed to list floatingips: %s", err.Error())
			errors.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		if len(fipList.Items) == 0 {
			app.Log.Warnf("no floatingip found for project %s in namespace %s to release for service %s/%s in cluster %s",
				fipReleaseRequest.Project, project.Namespace, fipReleaseRequest.ServiceNamespace, fipReleaseRequest.ServiceName, fipReleaseRequest.Cluster)
			errors.WriteJSONError(w, http.StatusNotFound, "no floatingip found to release")
			return
		}

		// Find the floating IP that contains the service to release
		var fipToUpdate fipv1beta2.FloatingIP
		found := false
		for i := range fipList.Items {
			fip := &fipList.Items[i]

			// Check if the floating IP has the requested IP address (if specified)
			if fipReleaseRequest.IPAddress != "" {
				if fip.Status.IPAddr != fipReleaseRequest.IPAddress {
					continue
				}
			}

			// If the FloatingIPGroup is given and we don't have a match we can skip this entry
			if fipReleaseRequest.FloatingIPGroup != "" {
				if fip.Labels["rancher.k8s.binbash.org/floatingip-group"] != fipReleaseRequest.FloatingIPGroup {
					continue
				}
			}

			// Look for service labels that match the requested service name and namespace
			for labelKey, labelValue := range fip.Labels {
				if strings.HasPrefix(labelKey, "rancher.k8s.binbash.org/service-") && strings.HasSuffix(labelKey, "-name") {
					// Extract the service ID from the label key (e.g., "service-0-name" -> "0")
					serviceID := strings.TrimPrefix(strings.TrimSuffix(labelKey, "-name"), "rancher.k8s.binbash.org/service-")
					namespaceKey := "rancher.k8s.binbash.org/service-" + serviceID + "-namespace"

					// Check if the namespace label exists and matches the requested service namespace
					if namespaceValue, ok := fip.Labels[namespaceKey]; ok {
						if namespaceValue == fipReleaseRequest.ServiceNamespace && labelValue == fipReleaseRequest.ServiceName {
							// Found the matching floating IP
							fipToUpdate = *fip
							found = true
							break
						}
					}
				}
			}
			if found {
				break
			}
		}

		if !found {
			app.Log.Warnf("no floatingip found for project %s in namespace %s to release for service %s/%s in cluster %s with IP %s",
				fipReleaseRequest.Project, project.Namespace, fipReleaseRequest.ServiceNamespace, fipReleaseRequest.ServiceName, fipReleaseRequest.Cluster, fipReleaseRequest.IPAddress)
			errors.WriteJSONError(w, http.StatusNotFound, "no floatingip found to release")
			return
		}

		// Find and delete the service labels that match the requested service name and namespace
		// Look for all service-<id>-name labels and find the one matching the request
		for labelKey, labelValue := range fipToUpdate.Labels {
			if strings.HasPrefix(labelKey, "rancher.k8s.binbash.org/service-") && strings.HasSuffix(labelKey, "-name") {
				// Extract the service ID from the label key (e.g., "service-0-name" -> "0")
				serviceID := strings.TrimPrefix(strings.TrimSuffix(labelKey, "-name"), "rancher.k8s.binbash.org/service-")
				namespaceKey := "rancher.k8s.binbash.org/service-" + serviceID + "-namespace"

				// Check if the namespace label exists and matches the requested service namespace
				if namespaceValue, ok := fipToUpdate.Labels[namespaceKey]; ok {
					if namespaceValue == fipReleaseRequest.ServiceNamespace && labelValue == fipReleaseRequest.ServiceName {
						// Found the matching service labels, delete them
						delete(fipToUpdate.Labels, labelKey)
						delete(fipToUpdate.Labels, namespaceKey)
						app.Log.Infof("Deleted service labels %s and %s for service %s/%s",
							labelKey, namespaceKey, fipReleaseRequest.ServiceNamespace, fipReleaseRequest.ServiceName)
						break
					}
				}
			}
		}

		// Check if this is the last service before removing the floatingip-group label
		if fipToUpdate.Labels["rancher.k8s.binbash.org/floatingip-group"] != "" {
			// Count remaining service labels
			remainingServices := 0
			for labelKey := range fipToUpdate.Labels {
				if strings.HasPrefix(labelKey, "rancher.k8s.binbash.org/service-") && strings.HasSuffix(labelKey, "-name") {
					remainingServices++
				}
			}
			// Only delete the floatingip-group label if no services remain
			if remainingServices == 0 {
				delete(fipToUpdate.Labels, "rancher.k8s.binbash.org/floatingip-group")
			}
		}

		// Check if there are still service-<id>-name and service-<id>-namespace labels remaining
		// If so, skip the cluster-name label deletion
		hasServiceLabels := false
		for labelKey := range fipToUpdate.Labels {
			if strings.HasPrefix(labelKey, "rancher.k8s.binbash.org/service-") && strings.HasSuffix(labelKey, "-name") {
				hasServiceLabels = true
				break
			}
		}

		if !hasServiceLabels {
			delete(fipToUpdate.Labels, "rancher.k8s.binbash.org/cluster-name")
		}

		// the status assigned and conditions will be updated by the rancher-fip-manager controller

		err = app.FipRestClient.Update(r.Context(), &fipToUpdate)
		if err != nil {
			app.Log.Errorf("failed to update floatingip: %s", err.Error())
			errors.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		app.Log.Infof("Released FloatingIP %s in object %s/%s", fipReleaseRequest.IPAddress, fipToUpdate.Namespace, fipToUpdate.Name)

		fipReleaseResponse := types.FIPReleaseResponse{
			Status:  "released",
			Message: "Floating IP released successfully",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(fipReleaseResponse)
	}
}

// FIPListHandler handles requests to list all floating IPs for a given project.
func FIPListHandler(app *types.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app.Log.Info("FIPListHandler called")
		var fipListRequest types.FIPListRequest
		if err := json.NewDecoder(r.Body).Decode(&fipListRequest); err != nil {
			errors.WriteJSONError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		// Find the project namespace
		var projects managementv3.ProjectList
		gvr := schema.GroupVersionResource{
			Group:    "management.cattle.io",
			Version:  "v3",
			Resource: "projects",
		}

		list, err := app.DynamicClient.Resource(gvr).List(r.Context(), metav1.ListOptions{})
		if err != nil {
			errors.WriteJSONError(w, http.StatusInternalServerError, "Failed to list projects")
			app.Log.Errorf("error gathering project list: %s", err.Error())
			return
		}

		if err = runtime.DefaultUnstructuredConverter.FromUnstructured(list.UnstructuredContent(), &projects); err != nil {
			errors.WriteJSONError(w, http.StatusInternalServerError, "Failed to parse projects")
			app.Log.Errorf("error parsing project list: %s", err.Error())
			return
		}

		var project managementv3.Project
		projectFound := false
		for _, p := range projects.Items {
			if p.Name == fipListRequest.Project {
				project = p
				projectFound = true
				break
			}
		}

		if !projectFound {
			errors.WriteJSONError(w, http.StatusBadRequest, "Project not found")
			app.Log.Errorf("project not found: %s", fipListRequest.Project)
			return
		}

		// List all floating IPs for the project
		fipList := &fipv1beta2.FloatingIPList{}
		err = app.FipRestClient.List(r.Context(), fipList, client.InNamespace(project.Namespace), client.MatchingLabels{
			"rancher.k8s.binbash.org/project-name": fipListRequest.Project,
		})
		if err != nil {
			app.Log.Errorf("failed to list floatingips: %s", err.Error())
			errors.WriteJSONError(w, http.StatusInternalServerError, "failed to list floating IPs")
			return
		}

		var floatingIPs []types.FloatingIP
		for _, item := range fipList.Items {
			if item.Spec.FloatingIPPool == fipListRequest.FloatingIPPool {
				if item.Spec.IPAddr != nil {
					// Only return the floating IP if it is assigned to the cluster or if the cluster is not specified
					if item.Labels["rancher.k8s.binbash.org/cluster-name"] == fipListRequest.Cluster || item.Status.Assigned == nil {
						// Iterate through all service-<id>-name and service-<id>-namespace labels
						// and create a FloatingIP entry for each one
						serviceIDs := make(map[string]bool)
						for key := range item.Labels {
							if strings.HasPrefix(key, "rancher.k8s.binbash.org/service-") && strings.HasSuffix(key, "-name") {
								prefix := "rancher.k8s.binbash.org/service-"
								suffix := "-name"
								idStr := strings.TrimPrefix(key, prefix)
								idStr = strings.TrimSuffix(idStr, suffix)
								serviceIDs[idStr] = true
							}
						}

						// Create a FloatingIP for each service ID found
						for serviceID := range serviceIDs {
							fip := types.FloatingIP{
								Project:          item.Labels["rancher.k8s.binbash.org/project-name"],
								Cluster:          item.Labels["rancher.k8s.binbash.org/cluster-name"],
								FloatingIPPool:   item.Spec.FloatingIPPool,
								ServiceNamespace: item.Labels["rancher.k8s.binbash.org/service-"+serviceID+"-namespace"],
								ServiceName:      item.Labels["rancher.k8s.binbash.org/service-"+serviceID+"-name"],
								IPAddress:        *item.Spec.IPAddr,
							}
							if item.Labels["rancher.k8s.binbash.org/floatingip-group"] != "" {
								fip.FloatingIPGroup = item.Labels["rancher.k8s.binbash.org/floatingip-group"]
							}
							floatingIPs = append(floatingIPs, fip)
						}
					}
				}
			}
		}

		fipListResponse := types.FIPListResponse{
			ClientSecret: fipListRequest.ClientSecret,
			Cluster:      fipListRequest.Cluster,
			Project:      fipListRequest.Project,
			FloatingIPs:  floatingIPs,
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(fipListResponse)
	}
}

// FIPDeleteHandler handles requests to delete a floating IP.
// It finds and deletes the corresponding FloatingIP custom resource.
func FIPDeleteHandler(app *types.App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		app.Log.Info("FIPDeleteHandler called")
		var fipDeleteRequest types.FIPDeleteRequest
		if err := json.NewDecoder(r.Body).Decode(&fipDeleteRequest); err != nil {
			errors.WriteJSONError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		// Find the project namespace
		var projects managementv3.ProjectList
		gvr := schema.GroupVersionResource{
			Group:    "management.cattle.io",
			Version:  "v3",
			Resource: "projects",
		}

		list, err := app.DynamicClient.Resource(gvr).List(r.Context(), metav1.ListOptions{})
		if err != nil {
			errors.WriteJSONError(w, http.StatusInternalServerError, "Failed to list projects")
			app.Log.Errorf("error gathering cluster list: %s", err.Error())
			return
		}

		if err = runtime.DefaultUnstructuredConverter.FromUnstructured(list.UnstructuredContent(), &projects); err != nil {
			errors.WriteJSONError(w, http.StatusInternalServerError, "Failed to parse projects")
			app.Log.Errorf("error parsing cluster list: %s", err.Error())
			return
		}

		var project managementv3.Project
		projectFound := false
		for _, p := range projects.Items {
			if p.Name == fipDeleteRequest.Project {
				project = p
				projectFound = true
				break
			}
		}

		if !projectFound {
			errors.WriteJSONError(w, http.StatusBadRequest, "Project not found")
			app.Log.Errorf("project not found: %s", fipDeleteRequest.Project)
			return
		}

		// List floating IPs in the project's namespace
		fipList := &fipv1beta2.FloatingIPList{}
		err = app.FipRestClient.List(r.Context(), fipList, client.InNamespace(project.Namespace))
		if err != nil {
			app.Log.Errorf("failed to list floatingips: %s", err.Error())
			errors.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		var fipToDelete *fipv1beta2.FloatingIP
		for i, fip := range fipList.Items {
			if fip.Spec.IPAddr != nil && *fip.Spec.IPAddr == fipDeleteRequest.IPAddress {
				fipToDelete = &fipList.Items[i]
				break
			}
		}

		if fipToDelete == nil {
			app.Log.Warnf("no floatingip found with address %s for project %s in namespace %s",
				fipDeleteRequest.IPAddress, fipDeleteRequest.Project, project.Namespace)
			errors.WriteJSONError(w, http.StatusNotFound, "no floatingip found to delete")
			return
		}

		err = app.FipRestClient.Delete(r.Context(), fipToDelete)
		if err != nil {
			app.Log.Errorf("failed to delete floatingip: %s", err.Error())
			errors.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		app.Log.Infof("Deleted FloatingIP %s/%s with IP %s", fipToDelete.Namespace, fipToDelete.Name, fipDeleteRequest.IPAddress)

		fipDeleteResponse := types.FIPDeleteResponse{
			Status:  "deleted",
			Message: "Floating IP deleted successfully",
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(fipDeleteResponse)
	}
}
