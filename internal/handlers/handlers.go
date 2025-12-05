// Package handlers implements the HTTP handlers for the API endpoints.
package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/joeyloman/rancher-fip-api-server/internal/auth"
	"github.com/joeyloman/rancher-fip-api-server/internal/errors"
	"github.com/joeyloman/rancher-fip-api-server/internal/kubebuilder"
	"github.com/joeyloman/rancher-fip-api-server/pkg/types"
	fipv1beta1 "github.com/joeyloman/rancher-fip-manager/pkg/apis/rancher.k8s.binbash.org/v1beta1"
	managementv3 "github.com/rancher/rancher/pkg/apis/management.cattle.io/v3"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

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

		var floatingIP *fipv1beta1.FloatingIP
		if fipRequest.IPAddress != "" {
			fipList := &fipv1beta1.FloatingIPList{}
			if err := app.FipRestClient.List(r.Context(), fipList, client.InNamespace(project.Namespace)); err != nil {
				app.Log.Errorf("failed to list floatingips: %s", err.Error())
				errors.WriteJSONError(w, http.StatusInternalServerError, "failed to list existing floating IPs")
				return
			}

			var existingFIP *fipv1beta1.FloatingIP
			for i := range fipList.Items {
				// Check of the FloatingIP belongs to the project and equals the requested IP
				if fipList.Items[i].Labels["rancher.k8s.binbash.org/project-name"] == project.Name && fipList.Items[i].Spec.IPAddr != nil && *fipList.Items[i].Spec.IPAddr == fipRequest.IPAddress {
					existingFIP = &fipList.Items[i]
					break
				}
			}

			if existingFIP != nil {
				// FIP with requested IP exists
				if existingFIP.Status.Assigned != nil {
					// IP is already assigned, which is an error condition
					errors.WriteJSONError(w, http.StatusConflict, "IP address is already assigned")
					app.Log.Errorf("requested ip %s is already assigned", fipRequest.IPAddress)
					return
				}
				// It exists but is not assigned, so we can use it.
				floatingIP = existingFIP
				if floatingIP.Labels == nil {
					floatingIP.Labels = make(map[string]string)
				}
				floatingIP.Labels["rancher.k8s.binbash.org/project-name"] = project.Name
				floatingIP.Labels["rancher.k8s.binbash.org/cluster-name"] = fipRequest.Cluster
				floatingIP.Labels["rancher.k8s.binbash.org/service-name"] = fipRequest.ServiceName
				floatingIP.Labels["rancher.k8s.binbash.org/service-namespace"] = fipRequest.ServiceNamespace

				if err := app.FipRestClient.Update(r.Context(), floatingIP); err != nil {
					app.Log.Errorf("failed to update floatingip: %s", err.Error())
					errors.WriteJSONError(w, http.StatusInternalServerError, "failed to update floating IP")
					return
				}
				app.Log.Infof("Updated existing FloatingIP %s/%s with new service labels", floatingIP.Namespace, floatingIP.Name)
			} else {
				// FIP with requested IP does not exist, so create it
				floatingIP = &fipv1beta1.FloatingIP{
					ObjectMeta: metav1.ObjectMeta{
						GenerateName: "fip-",
						Namespace:    project.Namespace,
						Labels: map[string]string{
							"rancher.k8s.binbash.org/project-name":      project.Name,
							"rancher.k8s.binbash.org/cluster-name":      fipRequest.Cluster,
							"rancher.k8s.binbash.org/service-name":      fipRequest.ServiceName,
							"rancher.k8s.binbash.org/service-namespace": fipRequest.ServiceNamespace,
						},
					},
					Spec: fipv1beta1.FloatingIPSpec{
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
			// Check if there are unassigned floatingips in the project, if so use one of them
			fipList := &fipv1beta1.FloatingIPList{}
			if err := app.FipRestClient.List(r.Context(), fipList, client.InNamespace(project.Namespace)); err != nil {
				app.Log.Errorf("failed to list floatingips: %s", err.Error())
				errors.WriteJSONError(w, http.StatusInternalServerError, "failed to list existing floating IPs")
				return
			}

			var existingFIP *fipv1beta1.FloatingIP
			for i := range fipList.Items {
				// Check of the FloatingIP belongs to the project and is not assigned
				if fipList.Items[i].Labels["rancher.k8s.binbash.org/project-name"] == project.Name && fipList.Items[i].Status.IPAddr != "" && fipList.Items[i].Status.Assigned == nil {
					existingFIP = &fipList.Items[i]
					break
				}
			}

			if existingFIP != nil {
				// It exists but is not assigned, so we can use it.
				floatingIP = existingFIP
				if floatingIP.Labels == nil {
					floatingIP.Labels = make(map[string]string)
				}
				floatingIP.Labels["rancher.k8s.binbash.org/project-name"] = project.Name
				floatingIP.Labels["rancher.k8s.binbash.org/cluster-name"] = fipRequest.Cluster
				floatingIP.Labels["rancher.k8s.binbash.org/service-name"] = fipRequest.ServiceName
				floatingIP.Labels["rancher.k8s.binbash.org/service-namespace"] = fipRequest.ServiceNamespace

				if err := app.FipRestClient.Update(r.Context(), floatingIP); err != nil {
					app.Log.Errorf("failed to update floatingip: %s", err.Error())
					errors.WriteJSONError(w, http.StatusInternalServerError, "failed to update floating IP")
					return
				}
				app.Log.Infof("Updated existing FloatingIP %s/%s with new service labels", floatingIP.Namespace, floatingIP.Name)
			} else {
				// No IP address requested, create a new one
				floatingIP = &fipv1beta1.FloatingIP{
					ObjectMeta: metav1.ObjectMeta{
						GenerateName: "fip-",
						Namespace:    project.Namespace,
						Labels: map[string]string{
							"rancher.k8s.binbash.org/project-name":      project.Name,
							"rancher.k8s.binbash.org/cluster-name":      fipRequest.Cluster,
							"rancher.k8s.binbash.org/service-name":      fipRequest.ServiceName,
							"rancher.k8s.binbash.org/service-namespace": fipRequest.ServiceNamespace,
						},
					},
					Spec: fipv1beta1.FloatingIPSpec{
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

		var ip string
		ip, err = kubebuilder.WatchFloatingIP(ctx, app.FipRestClient, floatingIP.Namespace, floatingIP.Name)
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

		fipResponse := types.FIPResponse{
			Status:           "approved",
			ClientSecret:     fipRequest.ClientSecret,
			Cluster:          fipRequest.Cluster,
			Project:          fipRequest.Project,
			FloatingIPPool:   fipRequest.FloatingIPPool,
			ServiceNamespace: fipRequest.ServiceNamespace,
			ServiceName:      fipRequest.ServiceName,
			IPAddress:        ip,
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
		fipList := &fipv1beta1.FloatingIPList{}
		err = app.FipRestClient.List(r.Context(), fipList, client.InNamespace(project.Namespace), client.MatchingLabels{
			"rancher.k8s.binbash.org/project-name":      fipReleaseRequest.Project,
			"rancher.k8s.binbash.org/cluster-name":      fipReleaseRequest.Cluster,
			"rancher.k8s.binbash.org/service-name":      fipReleaseRequest.ServiceName,
			"rancher.k8s.binbash.org/service-namespace": fipReleaseRequest.ServiceNamespace,
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

		// Update the floating IP to release it
		fipToUpdate := fipList.Items[0]
		delete(fipToUpdate.Labels, "rancher.k8s.binbash.org/cluster-name")
		delete(fipToUpdate.Labels, "rancher.k8s.binbash.org/service-name")
		delete(fipToUpdate.Labels, "rancher.k8s.binbash.org/service-namespace")

		// the status assigned and conditions will be updated by the rancher-fip-manager controller

		err = app.FipRestClient.Update(r.Context(), &fipToUpdate)
		if err != nil {
			app.Log.Errorf("failed to update floatingip: %s", err.Error())
			errors.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		app.Log.Infof("Released FloatingIP %s/%s", fipToUpdate.Namespace, fipToUpdate.Name)

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
		fipList := &fipv1beta1.FloatingIPList{}
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
						fip := types.FloatingIP{
							Project:          item.Labels["rancher.k8s.binbash.org/project-name"],
							Cluster:          item.Labels["rancher.k8s.binbash.org/cluster-name"],
							FloatingIPPool:   item.Spec.FloatingIPPool,
							ServiceNamespace: item.Labels["rancher.k8s.binbash.org/service-namespace"],
							ServiceName:      item.Labels["rancher.k8s.binbash.org/service-name"],
							IPAddress:        *item.Spec.IPAddr,
						}
						floatingIPs = append(floatingIPs, fip)
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
		fipList := &fipv1beta1.FloatingIPList{}
		err = app.FipRestClient.List(r.Context(), fipList, client.InNamespace(project.Namespace))
		if err != nil {
			app.Log.Errorf("failed to list floatingips: %s", err.Error())
			errors.WriteJSONError(w, http.StatusInternalServerError, err.Error())
			return
		}

		var fipToDelete *fipv1beta1.FloatingIP
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
