package report

import (
	"context"
	"errors"
	"fmt"

	"strings"

	"github.com/kubewarden/audit-scanner/internal/constants"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	errorMachinery "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/util/retry"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	polReport "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

// PolicyReportStore caches the latest version of PolicyReports
type PolicyReportStore struct {
	// For now, the store has K8s/etcd backend only
	// client used to instantiate PolicyReport resources
	client client.Client
}

// NewPolicyReportStore construct a PolicyReportStore, initializing the
// clusterwide ClusterPolicyReport and namesapcedPolicyReports.
func NewPolicyReportStore() (*PolicyReportStore, error) {
	config := ctrl.GetConfigOrDie()
	customScheme := scheme.Scheme
	customScheme.AddKnownTypes(
		polReport.SchemeGroupVersion,
		&polReport.PolicyReport{},
		&polReport.ClusterPolicyReport{},
		&polReport.PolicyReportList{},
		&polReport.ClusterPolicyReportList{},
	)
	metav1.AddToGroupVersion(customScheme, polReport.SchemeGroupVersion)
	client, err := client.New(config, client.Options{Scheme: customScheme})
	if err != nil {
		return nil, fmt.Errorf("failed when creating new client: %w", err)
	}

	return &PolicyReportStore{client: client}, nil
}

// MockNewPolicyReportStore constructs a PolicyReportStore, initializing the
// clusterwide ClusterPolicyReport and namespacedPolicyReports, but setting the
// client. Useful for testing.
func MockNewPolicyReportStore(client client.Client) *PolicyReportStore {
	return &PolicyReportStore{client: client}
}

// Get PolicyReport by namespace
func (s *PolicyReportStore) GetPolicyReport(namespace string) (PolicyReport, error) {
	report := polReport.PolicyReport{}
	getErr := s.client.Get(context.TODO(), types.NamespacedName{
		Namespace: namespace,
		Name:      getNamespacedReportName(namespace),
	}, &report)
	if getErr != nil {
		if errorMachinery.IsNotFound(getErr) {
			return PolicyReport{}, constants.ErrResourceNotFound
		}
		return PolicyReport{}, getErr
	}
	policyReport := &PolicyReport{
		report,
	}
	log.Debug().Dict("dict", zerolog.Dict().
		Str("report name", report.GetName()).
		Str("report ns", report.GetNamespace()).
		Str("report resourceVersion", report.GetResourceVersion())).
		Msg("PolicyReport found")
	return *policyReport, nil
}

// Get the ClusterPolicyReport
func (s *PolicyReportStore) GetClusterPolicyReport(name string) (ClusterPolicyReport, error) {
	result := polReport.ClusterPolicyReport{}
	if !strings.HasPrefix(name, PrefixNameClusterPolicyReport) {
		name = getClusterReportName(name)
	}
	getErr := s.client.Get(context.Background(), client.ObjectKey{Name: name}, &result)
	if getErr != nil {
		if errorMachinery.IsNotFound(getErr) {
			return ClusterPolicyReport{}, constants.ErrResourceNotFound
		}
		return ClusterPolicyReport{}, getErr
	}
	return ClusterPolicyReport{
		result,
	}, nil
}

// Update namespaced PolicyReport
func (s *PolicyReportStore) UpdatePolicyReport(report *PolicyReport) error {
	err := s.client.Update(context.Background(), &report.PolicyReport)
	if err != nil {
		return err
	}
	summary, _ := report.GetSummaryJSON()
	log.Info().
		Dict("dict", zerolog.Dict().
			Str("report name", report.GetName()).
			Str("report ns", report.GetNamespace()).
			Str("report resourceVersion", report.GetResourceVersion()).
			Str("summary", summary),
		).Msg("updated PolicyReport")
	return nil
}

// Update ClusterPolicyReport or PolicyReport. ns argument is used in case
// of namespaced PolicyReport
func (s *PolicyReportStore) UpdateClusterPolicyReport(report *ClusterPolicyReport) error {
	err := s.client.Update(context.Background(), &report.ClusterPolicyReport)
	if err != nil {
		return err
	}
	summary, _ := report.GetSummaryJSON()
	log.Info().
		Dict("dict", zerolog.Dict().
			Str("report name", report.GetName()).
			Str("report ns", report.GetNamespace()).
			Str("summary", summary),
		).Msg("updated ClusterPolicyReport")
	return nil
}

// Delete PolicyReport by namespace
func (s *PolicyReportStore) RemovePolicyReport(namespace string) error {
	if report, err := s.GetPolicyReport(namespace); err == nil {
		err := s.client.Delete(context.Background(), &report.PolicyReport)
		if err != nil {
			return err
		}
	}
	return nil
}

// Delete all namespaced PolicyReports
func (s *PolicyReportStore) RemoveAllNamespacedPolicyReports() error {
	err := s.client.DeleteAllOf(context.Background(), &polReport.PolicyReport{},
		client.MatchingLabels(map[string]string{
			LabelAppManagedBy: LabelApp,
		}))
	if err != nil {
		return err
	}
	return nil
}

// createPolicyReport should not be called directly. Use the SavePolicyReport
func (s *PolicyReportStore) createPolicyReport(report *PolicyReport) error {
	err := s.client.Create(context.Background(), &report.PolicyReport)
	if err != nil {
		return fmt.Errorf("create failed: %w", err)
	}
	summary, _ := report.GetSummaryJSON()
	log.Info().
		Dict("dict", zerolog.Dict().
			Str("report name", report.GetName()).
			Str("report ns", report.GetNamespace()).
			Str("summary", summary),
		).Msg("created PolicyReport")
	return nil
}

// createClusterPolicyReport should not be called directly. Use the SaveClusterPolicyReport
func (s *PolicyReportStore) createClusterPolicyReport(report *ClusterPolicyReport) error {
	err := s.client.Create(context.Background(), &report.ClusterPolicyReport)
	if err != nil {
		return fmt.Errorf("create failed: %w", err)
	}
	summary, _ := report.GetSummaryJSON()
	log.Info().
		Dict("dict", zerolog.Dict().
			Str("report name", report.GetName()).
			Str("report ns", report.GetNamespace()).
			Str("summary", summary),
		).Msg("created ClusterPolicyReport")
	return nil
}

// SavePolicyReport instantiates the passed namespaced PolicyReport if it doesn't exist, or
// updates it if one is found
func (s *PolicyReportStore) SavePolicyReport(report *PolicyReport) error {
	// Check for existing Policy Report
	_, getErr := s.GetPolicyReport(report.GetNamespace())
	if getErr != nil {
		// Create new Policy Report if not found
		if errors.Is(getErr, constants.ErrResourceNotFound) {
			return s.createPolicyReport(report)
		}
		return getErr
	}
	// Update existing Policy Report
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// get the latest report version to be updated
		latestReport, err := s.GetPolicyReport(report.GetNamespace())
		if err != nil {
			return err
		}
		latestReport.Summary = report.Summary
		latestReport.Results = report.Results
		return s.UpdatePolicyReport(&latestReport)
	})
	if retryErr != nil {
		return fmt.Errorf("update failed: %w", retryErr)
	}
	return nil
}

// SavePolicyClusterPolicyReport instantiates the ClusterPolicyReport if it doesn't exist, or
// updates it one is found
func (s *PolicyReportStore) SaveClusterPolicyReport(report *ClusterPolicyReport) error {
	// Check for existing Policy Report
	_, getErr := s.GetClusterPolicyReport(report.GetName())
	if getErr != nil {
		// Create new Policy Report if not found
		if errors.Is(getErr, constants.ErrResourceNotFound) {
			return s.createClusterPolicyReport(report)
		}
		return getErr
	}
	// Update existing Policy Report
	retryErr := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		// get the latest report version to be updated
		latestReport, err := s.GetClusterPolicyReport(report.GetName())
		if err != nil {
			return err
		}
		latestReport.Summary = report.Summary
		latestReport.Results = report.Results
		return s.UpdateClusterPolicyReport(&latestReport)
	})
	if retryErr != nil {
		return fmt.Errorf("update failed: %w", retryErr)
	}
	return nil
}
