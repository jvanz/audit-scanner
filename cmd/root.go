package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/google/uuid"
	"github.com/kubewarden/audit-scanner/internal/k8s"
	"github.com/kubewarden/audit-scanner/internal/policies"
	"github.com/kubewarden/audit-scanner/internal/report"
	"github.com/kubewarden/audit-scanner/internal/scanner"
	"github.com/kubewarden/audit-scanner/internal/scheme"
	"github.com/spf13/cobra"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	defaultKubewardenNamespace = "kubewarden"
	defaultParallelResources   = 100
	defaultParallelPolicies    = 5
	defaultParallelNamespaces  = 1
	defaultPageSize            = 100
)

//nolint:gocognit,funlen // This function is the CLI entrypoint and it's expected to be long.
func NewRootCommand() *cobra.Command {
	var (
		level        string   // log level.
		outputScan   bool     // print result of scan as JSON to stdout.
		skippedNs    []string // list of namespaces to be skipped from scan.
		insecureSSL  bool     // skip SSL cert validation when connecting to PolicyServers endpoints.
		disableStore bool     // disable storing the results in the k8s cluster.
	)

	// rootCmd represents the base command when called without any subcommands.
	rootCmd := &cobra.Command{
		Use:   "audit-scanner",
		Short: "Reports evaluation of existing Kubernetes resources with your already deployed Kubewarden policies",
		Long: `Scans resources in your kubernetes cluster with your already deployed Kubewarden policies.
Each namespace will have a PolicyReport with the outcome of the scan for resources within this namespace.
There will be a ClusterPolicyReport with results for cluster-wide resources.`,

		RunE: func(cmd *cobra.Command, _ []string) error {
			namespace, err := cmd.Flags().GetString("namespace")
			if err != nil {
				return err
			}
			kubewardenNamespace, err := cmd.Flags().GetString("kubewarden-namespace")
			if err != nil {
				return err
			}
			clusterWide, err := cmd.Flags().GetBool("cluster")
			if err != nil {
				return err
			}
			policyServerURL, err := cmd.Flags().GetString("policy-server-url")
			if err != nil {
				return err
			}
			caFile, err := cmd.Flags().GetString("extra-ca")
			if err != nil {
				return err
			}
			clientCertFile, err := cmd.Flags().GetString("client-cert")
			if err != nil {
				return err
			}
			clientKeyFile, err := cmd.Flags().GetString("client-key")
			if err != nil {
				return err
			}
			parallelNamespacesAudits, err := cmd.Flags().GetInt("parallel-namespaces")
			if err != nil {
				return err
			}
			parallelResourcesAudits, err := cmd.Flags().GetInt("parallel-resources")
			if err != nil {
				return err
			}
			parallelPoliciesAudit, err := cmd.Flags().GetInt("parallel-policies")
			if err != nil {
				return err
			}
			pageSize, err := cmd.Flags().GetInt("page-size")
			if err != nil {
				return err
			}

			config := ctrl.GetConfigOrDie()
			dynamicClient := dynamic.NewForConfigOrDie(config)
			clientset := kubernetes.NewForConfigOrDie(config)

			auditScheme, err := scheme.NewScheme()
			if err != nil {
				return err
			}
			client, err := client.New(config, client.Options{Scheme: auditScheme})
			if err != nil {
				return err
			}
			logger := slog.New(NewHandler(os.Stdout, level))
			policiesClient, err := policies.NewClient(client, kubewardenNamespace, policyServerURL, logger)
			if err != nil {
				return err
			}
			k8sClient, err := k8s.NewClient(dynamicClient, clientset, kubewardenNamespace, skippedNs, int64(pageSize), logger)
			if err != nil {
				return err
			}
			policyReportStore := report.NewPolicyReportStore(client, logger)

			scannerConfig := scanner.Config{
				PoliciesClient:    policiesClient,
				K8sClient:         k8sClient,
				PolicyReportStore: policyReportStore,
				TLS: scanner.TLSConfig{
					Insecure:       insecureSSL,
					CAFile:         caFile,
					ClientCertFile: clientCertFile,
					ClientKeyFile:  clientKeyFile,
				},
				Parallelization: scanner.ParallelizationConfig{
					ParallelNamespacesAudits: parallelNamespacesAudits,
					ParallelResourcesAudits:  parallelResourcesAudits,
					PoliciesAudits:           parallelPoliciesAudit,
				},
				OutputScan:   outputScan,
				DisableStore: disableStore,
				Logger:       logger.With("component", "scanner"),
			}

			scanner, err := scanner.NewScanner(scannerConfig)
			if err != nil {
				return err
			}
			return startScanner(namespace, clusterWide, scanner)
		},
	}

	// make sure we always get json formatted errors, even for flag errors
	rootCmd.SilenceErrors = true
	rootCmd.SilenceUsage = true

	rootCmd.Flags().StringP("namespace", "n", "", "namespace to be evaluated")
	rootCmd.Flags().BoolP("cluster", "c", false, "scan cluster wide resources")
	rootCmd.Flags().StringP("kubewarden-namespace", "k", defaultKubewardenNamespace, "namespace where the Kubewarden components (e.g. PolicyServer) are installed (required)")
	rootCmd.Flags().StringP("policy-server-url", "u", "", "URI to the PolicyServers the Audit Scanner will query. Example: https://localhost:3000. Useful for out-of-cluster debugging")
	rootCmd.Flags().StringVarP(&level, "loglevel", "l", "", fmt.Sprintf("level of the logs. Supported values are: %v", SupportedLogLevels()))
	rootCmd.Flags().BoolVarP(&outputScan, "output-scan", "o", false, "print result of scan in JSON to stdout")
	rootCmd.Flags().StringSliceVarP(&skippedNs, "ignore-namespaces", "i", nil, "comma separated list of namespace names to be skipped from scan. This flag can be repeated")
	rootCmd.Flags().BoolVar(&insecureSSL, "insecure-ssl", false, "skip SSL cert validation when connecting to PolicyServers endpoints. Useful for development")
	rootCmd.Flags().StringP("extra-ca", "f", "", "File path to CA cert in PEM format of PolicyServer endpoints")
	rootCmd.Flags().StringP("client-cert", "", "", "File path to client cert in PEM format used for mTLS communication with the PolicyServer endpoints")
	rootCmd.Flags().StringP("client-key", "", "", "File path to client key in PEM format used for mTLS communication with the PolicyServer endpoints")
	rootCmd.MarkFlagsRequiredTogether("client-cert", "client-key")
	rootCmd.Flags().BoolVar(&disableStore, "disable-store", false, "disable storing the results in the k8s cluster")
	rootCmd.Flags().IntP("parallel-namespaces", "", defaultParallelNamespaces, "number of Namespaces to scan in parallel")
	rootCmd.Flags().IntP("parallel-resources", "", defaultParallelResources, "number of resources to scan in parallel")
	rootCmd.Flags().IntP("parallel-policies", "", defaultParallelPolicies, "number of policies to evaluate for a given resource in parallel")
	rootCmd.Flags().IntP("page-size", "", defaultPageSize, "number of resources to fetch from the Kubernetes API server when paginating")

	return rootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute(rootCmd *cobra.Command) {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error on cmd.Execute(): %s\n", err.Error())
		os.Exit(1)
	}
}

func startScanner(namespace string, clusterWide bool, scanner *scanner.Scanner) error {
	if clusterWide && namespace != "" {
		fmt.Fprintln(os.Stderr, "Cannot scan cluster wide and only a namespace at the same time")
	}

	runUID := uuid.New().String()
	ctx := context.Background()
	if clusterWide {
		// only scan clusterwide
		return scanner.ScanClusterWideResources(ctx, runUID)
	}
	if namespace != "" {
		// only scan namespace
		return scanner.ScanNamespace(ctx, namespace, runUID)
	}

	// neither clusterWide flag nor namespace was provided, default
	// behaviour of scanning cluster wide and all ns
	if err := scanner.ScanClusterWideResources(ctx, runUID); err != nil {
		return err
	}
	return scanner.ScanAllNamespaces(ctx, runUID)
}
