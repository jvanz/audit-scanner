package scanner

import (
	"github.com/kubewarden/audit-scanner/internal/k8s"
	"github.com/kubewarden/audit-scanner/internal/policies"
	"github.com/kubewarden/audit-scanner/internal/report"
)

type ParallelizationConfig struct {
	ParallelNamespacesAudits int
	ParallelResourcesAudits  int
	PoliciesAudits           int
}

type TLSConfig struct {
	Insecure       bool
	CAFile         string
	ClientCertFile string
	ClientKeyFile  string
}

type Config struct {
	PoliciesClient    *policies.Client
	K8sClient         *k8s.Client
	PolicyReportStore report.ReportStore

	TLS             TLSConfig
	Parallelization ParallelizationConfig

	OutputScan    bool
	DisableStore  bool
	SUSEObsURL    string
	SUSEObsApiKey string
}
