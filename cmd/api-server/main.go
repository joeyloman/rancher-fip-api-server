package main

import (
	"context"
	"crypto/rsa"
	"flag"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"

	"github.com/gorilla/mux"
	"github.com/joeyloman/rancher-fip-api-server/internal/auth"
	"github.com/joeyloman/rancher-fip-api-server/internal/handlers"
	"github.com/joeyloman/rancher-fip-api-server/internal/middleware"
	"github.com/joeyloman/rancher-fip-api-server/pkg/types"
	fipv1beta1 "github.com/joeyloman/rancher-fip-manager/pkg/apis/rancher.k8s.binbash.org/v1beta1"
	"github.com/sirupsen/logrus"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	kubeconfig                        string
	kubecontext                       string
	leaderElect                       bool
	leaseLockName                     string
	leaseLockNamespace                string
	jwtGenerateKey                    bool
	jwtSecretName                     string
	jwtSecretNamespace                string
	authorizedProjectsSecretName      string
	authorizedProjectsSecretNamespace string
	rateLimitPerSecond                float64
	rateLimitBurst                    int
	listenAddress                     string
	tlsEnabled                        bool
	tlsCertFile                       string
	tlsKeyFile                        string
)

func main() {
	// Initialize logger
	log := logrus.New()
	log.SetFormatter(&logrus.JSONFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(logrus.InfoLevel)

	// Command-line flags
	flag.StringVar(&kubeconfig, "kubeconfig", os.Getenv("KUBECONFIG"), "Path to a kubeconfig file.")
	flag.StringVar(&kubecontext, "kubecontext", os.Getenv("KUBECONTEXT"), "The name of the kubeconfig context to use.")
	flag.BoolVar(&leaderElect, "leader-elect", true, "Enable leader election for controller.")
	flag.StringVar(&leaseLockName, "lease-lock-name", "rancher-fip-api-server-lock", "The name of the leader election lock.")
	flag.StringVar(&leaseLockNamespace, "lease-lock-namespace", "rancher-fip-manager", "The namespace of the leader election lock.")
	flag.BoolVar(&jwtGenerateKey, "jwt-generate-key", true, "Generate a new JWT private key.")
	flag.StringVar(&jwtSecretName, "jwt-secret-name", "jwt-private-key", "The name of the secret containing the JWT private key.")
	flag.StringVar(&jwtSecretNamespace, "jwt-secret-namespace", "rancher-fip-manager", "The namespace of the secret containing the JWT private key.")
	flag.Float64Var(&rateLimitPerSecond, "rate-limit-per-second", 10, "The number of requests allowed per second.")
	flag.IntVar(&rateLimitBurst, "rate-limit-burst", 20, "The burst number of requests allowed.")
	flag.StringVar(&listenAddress, "listen-address", ":8080", "The address to listen on for HTTP requests.")
	flag.BoolVar(&tlsEnabled, "tls-enabled", false, "Enable TLS for HTTPS.")
	flag.StringVar(&tlsCertFile, "tls-cert-file", "", "Path to the TLS certificate file.")
	flag.StringVar(&tlsKeyFile, "tls-key-file", "", "Path to the TLS key file.")
	flag.Parse()

	// Create root context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Set up signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigChan
		log.Info("Shutting down...")
		cancel()
	}()

	// Set up Kubernetes client
	var config *rest.Config
	var err error
	if kubeconfig != "" {
		log.Infof("Using kubeconfig file: %s", kubeconfig)
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		log.Info("Using in-cluster config")
		config, err = rest.InClusterConfig()
	}
	if err != nil {
		log.Fatalf("Failed to create Kubernetes config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create Kubernetes clientset: %v", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		log.Fatalf("Failed to create dynamic client: %v", err)
	}

	if !leaderElect {
		run(ctx, log, config, clientset, dynamicClient)
		logrus.Info("Controller finished")
		return
	}

	// Leader-election logic
	id := uuid.New().String()
	lock := &resourcelock.LeaseLock{
		LeaseMeta: metav1.ObjectMeta{
			Name:      leaseLockName,
			Namespace: leaseLockNamespace,
		},
		Client: clientset.CoordinationV1(),
		LockConfig: resourcelock.ResourceLockConfig{
			Identity: id,
		},
	}

	leaderelection.RunOrDie(ctx, leaderelection.LeaderElectionConfig{
		Lock:            lock,
		ReleaseOnCancel: true,
		LeaseDuration:   15 * time.Second,
		RenewDeadline:   10 * time.Second,
		RetryPeriod:     2 * time.Second,
		Callbacks: leaderelection.LeaderCallbacks{
			OnStartedLeading: func(ctx context.Context) {
				run(ctx, log, config, clientset, dynamicClient)
			},
			OnStoppedLeading: func() {
				logrus.Infof("leader lost: %s", id)
				os.Exit(0)
			},
			OnNewLeader: func(identity string) {
				if identity == id {
					// I just became the leader
					return
				}
				logrus.Infof("new leader elected: %s", identity)
			},
		},
	})
}

func run(ctx context.Context, log *logrus.Logger, config *rest.Config, clientset *kubernetes.Clientset, dynamicClient dynamic.Interface) {
	logrus.Info("Starting rancher-fip-api-server")

	var privateKey *rsa.PrivateKey
	privateKey, err := auth.GetPrivateKey(ctx, clientset, jwtSecretNamespace, jwtSecretName, "key")
	if err != nil {
		if k8serrors.IsNotFound(err) {
			if jwtGenerateKey {
				// Generate the private key
				privateKey, err := auth.GeneratePrivateKey()
				if err != nil {
					log.Fatalf("Failed to generate private key: %v", err)
				}
				// Save the key to the secret
				if err := auth.SavePrivateKey(ctx, clientset, jwtSecretNamespace, jwtSecretName, privateKey); err != nil {
					log.Fatalf("Failed to save private key: %v", err)
				}
			} else {
				log.Fatalf("Private key not found in secret %s/%s", jwtSecretNamespace, jwtSecretName)
			}
		} else {
			log.Fatalf("Failed to get private key: %v", err)
		}
	}

	fipScheme := runtime.NewScheme()
	fipv1beta1.AddToScheme(fipScheme)

	fipRestClient, err := client.New(config, client.Options{
		Scheme: fipScheme,
	})
	if err != nil {
		log.Fatalf("Failed to create fip rest client: %v", err)
	}

	app := &types.App{
		FipRestClient: fipRestClient,
		Clientset:     clientset,
		DynamicClient: dynamicClient,
		Log:           log,
		PrivateKey:    privateKey,
	}

	log.Infof("Successfully connected to Kubernetes cluster: %s", clientset.Discovery().RESTClient().Get().URL())

	// Set up HTTP server
	r := mux.NewRouter()
	r.Use(middleware.RateLimitMiddleware(rateLimitPerSecond, rateLimitBurst))
	r.HandleFunc("/v1/auth/token", handlers.TokenHandler(app)).Methods("POST")

	// Protected routes
	s := r.PathPrefix("/v1/fip").Subrouter()
	s.Use(middleware.AuthMiddleware(app))
	s.Use(middleware.AuthorizeMiddleware(app))
	s.HandleFunc("/request", handlers.FIPRequestHandler(app)).Methods("POST")
	s.HandleFunc("/release", handlers.FIPReleaseHandler(app)).Methods("POST")
	s.HandleFunc("/delete", handlers.FIPDeleteHandler(app)).Methods("DELETE")
	s.HandleFunc("/list", handlers.FIPListHandler(app)).Methods("POST")

	server := &http.Server{
		Addr:    listenAddress,
		Handler: r,
	}

	go func() {
		if tlsEnabled {
			log.Infof("Starting server on %s with TLS", listenAddress)
			if err := server.ListenAndServeTLS(tlsCertFile, tlsKeyFile); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Could not listen on %s: %v\n", listenAddress, err)
			}
		} else {
			log.Infof("Starting server on %s", listenAddress)
			if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Fatalf("Could not listen on %s: %v\n", listenAddress, err)
			}
		}
	}()

	// Wait for shutdown signal
	<-ctx.Done()

	// Shutdown the server gracefully
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Fatalf("Server shutdown failed: %v", err)
	}

	log.Info("Server gracefully stopped")
}
