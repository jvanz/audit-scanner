package report

import (
	"encoding/json"
	"fmt"
	"net/http"

	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

const DEFAULT_REPEAT_INTERVAL_DURATION = "1800s"
const DEFAULT_EXPIRE_INTERVAL_DURATION = "1800s"

// A mock used to validate the request sent to SUSE Observability
type MockRoundTripper struct {
	mock.Mock
}

func (m *MockRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	args := m.Called(req)
	return args.Get(0).(*http.Response), args.Error(1)
}

func TestSuseObsPayloadCreationFromPolicyReport(t *testing.T) {

	repeatInterval, err := time.ParseDuration(DEFAULT_REPEAT_INTERVAL_DURATION)
	require.NoError(t, err)
	expireInterval, err := time.ParseDuration(DEFAULT_EXPIRE_INTERVAL_DURATION)
	require.NoError(t, err)
	suseObsStore := NewSuseObsStore("apiKey", "https://suseobs.localhost", "urn:health:kubernetes:external-health", "cluster", repeatInterval, expireInterval)
	policyReport := &wgpolicy.PolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:            uuid.NewString(),
			Namespace:       "namespace",
			Labels:          map[string]string{},
			OwnerReferences: []metav1.OwnerReference{},
		},
		Scope: &corev1.ObjectReference{
			APIVersion:      "v1",
			Kind:            "Pod",
			Namespace:       "pod-namespace",
			Name:            "privileged-pod",
			UID:             types.UID(uuid.NewString()),
			ResourceVersion: "1234",
		},
		Summary: wgpolicy.PolicyReportSummary{
			Pass:  0, // count of policies with requirements met
			Fail:  0, // count of policies with requirements not met
			Warn:  0, // not used for now
			Error: 0, // count of policies that couldn't be evaluated
			Skip:  0, // count of policies that were not selected for evaluation
		},
		Results: []*wgpolicy.PolicyReportResult{
			{
				Result:      statusFail,
				Description: "priviledged pod not allowed",
				Policy:      "pod-privileged",
			},
			{
				Result:      statusPass,
				Description: "",
				Policy:      "ok-policy",
			},
			{
				Result:      statusFail,
				Description: "Invalid user",
				Policy:      "user-group-policy",
			},
		},
	}

	payload, err := suseObsStore.convertPolicyReportIntoSuseObsJsonPayload(policyReport)
	require.NoError(t, err)
	expectedPayload := SuseObsJsonPayload{
		ApiKey:           "apiKey",
		InternalHostname: "suseobs.localhost",
		Events:           nil,
		Metrics:          []interface{}{},
		ServiceChecks:    []interface{}{},
		Topologies:       []interface{}{},
		Health: []SuseObsHealthCheck{{
			ConsistencyModel: DEFAULT_CONSISTENCY_MODEL,
			Stream: SuseObsStream{
				Urn:         "urn:health:kubernetes:external-health",
				SubStreamId: "cluster",
			},
			CheckStates: []SuseObsCheckState{
				{
					CheckStateId:              "pod-privileged-pod-namespace-pod-privileged-pod-pod-privileged",
					Message:                   "priviledged pod not allowed",
					Health:                    "Deviating",
					TopologyElementIdentifier: "urn:kubernetes:/cluster:pod-namespace:pod/privileged-pod",
					Name:                      "pod-privileged",
				},
				{
					CheckStateId:              "ok-policy-pod-namespace-pod-privileged-pod-ok-policy",
					Message:                   "",
					Health:                    "Clear",
					TopologyElementIdentifier: "urn:kubernetes:/cluster:pod-namespace:pod/privileged-pod",
					Name:                      "ok-policy",
				},

				{
					CheckStateId:              "user-group-policy-pod-namespace-pod-privileged-pod-user-group-policy",
					Message:                   "Invalid user",
					Health:                    "Deviating",
					TopologyElementIdentifier: "urn:kubernetes:/cluster:pod-namespace:pod/privileged-pod",
					Name:                      "user-group-policy",
				},
			},
		}},
	}
	require.GreaterOrEqual(t, time.Now().Unix(), payload.CollectionTimestamp)
	expectedPayload.CollectionTimestamp = payload.CollectionTimestamp
	require.Equal(t, expectedPayload, *payload)
	_, err = json.Marshal(payload)
	require.NoError(t, err)
}

func TestSuseObsPayloadCreationFromClusterPolicyReport(t *testing.T) {
	repeatInterval, err := time.ParseDuration(DEFAULT_REPEAT_INTERVAL_DURATION)
	require.NoError(t, err)
	expireInterval, err := time.ParseDuration(DEFAULT_EXPIRE_INTERVAL_DURATION)
	require.NoError(t, err)
	suseObsStore := NewSuseObsStore("apiKey", "https://suseobs.localhost", "urn:health:kubernetes:external-health", "cluster", repeatInterval, expireInterval)
	policyReport := &wgpolicy.ClusterPolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:            uuid.NewString(),
			Namespace:       "namespace",
			Labels:          map[string]string{},
			OwnerReferences: []metav1.OwnerReference{},
		},
		Scope: &corev1.ObjectReference{
			APIVersion:      "v1",
			Kind:            "Pod",
			Namespace:       "pod-namespace",
			Name:            "privileged-pod",
			UID:             types.UID(uuid.NewString()),
			ResourceVersion: "1234",
		},
		Summary: wgpolicy.PolicyReportSummary{
			Pass:  0, // count of policies with requirements met
			Fail:  0, // count of policies with requirements not met
			Warn:  0, // not used for now
			Error: 0, // count of policies that couldn't be evaluated
			Skip:  0, // count of policies that were not selected for evaluation
		},
		Results: []*wgpolicy.PolicyReportResult{
			{
				Result:      statusFail,
				Description: "priviledged pod not allowed",
				Policy:      "pod-privileged",
			},
			{
				Result:      statusPass,
				Description: "",
				Policy:      "ok-policy",
			},
			{
				Result:      statusFail,
				Description: "Invalid user",
				Policy:      "user-group-policy",
			},
		},
	}

	payload, err := suseObsStore.convertClusterPolicyReportIntoSuseObsJsonPayload(policyReport)
	require.NoError(t, err)
	expectedPayload := SuseObsJsonPayload{
		ApiKey:           "apiKey",
		InternalHostname: "suseobs.localhost",
		Events:           nil,
		Metrics:          []interface{}{},
		ServiceChecks:    []interface{}{},
		Topologies:       []interface{}{},
		Health: []SuseObsHealthCheck{{
			ConsistencyModel: DEFAULT_CONSISTENCY_MODEL,
			Stream: SuseObsStream{
				Urn:         "urn:health:kubernetes:external-health",
				SubStreamId: "cluster",
			},
			CheckStates: []SuseObsCheckState{
				{
					CheckStateId:              "pod-privileged-pod-namespace-pod-privileged-pod-pod-privileged",
					Message:                   "priviledged pod not allowed",
					Health:                    "Deviating",
					TopologyElementIdentifier: "urn:kubernetes:/cluster:pod/privileged-pod",
					Name:                      "pod-privileged",
				},
				{
					CheckStateId:              "ok-policy-pod-namespace-pod-privileged-pod-ok-policy",
					Message:                   "",
					Health:                    "Clear",
					TopologyElementIdentifier: "urn:kubernetes:/cluster:pod/privileged-pod",
					Name:                      "ok-policy",
				},
				{
					CheckStateId:              "user-group-policy-pod-namespace-pod-privileged-pod-user-group-policy",
					Message:                   "Invalid user",
					Health:                    "Deviating",
					TopologyElementIdentifier: "urn:kubernetes:/cluster:pod/privileged-pod",
					Name:                      "user-group-policy",
				},
			},
		}},
	}
	require.GreaterOrEqual(t, time.Now().Unix(), payload.CollectionTimestamp)
	expectedPayload.CollectionTimestamp = payload.CollectionTimestamp
	require.Equal(t, expectedPayload, *payload)
	bytes, err := json.Marshal(payload)
	require.NoError(t, err)
	fmt.Println(string(bytes))
}

func TestSuseObsCheckHealthCheckCreationFromPolicyReport(t *testing.T) {
	policyReport := &wgpolicy.PolicyReport{
		ObjectMeta: metav1.ObjectMeta{
			Name:            uuid.NewString(),
			Namespace:       "namespace",
			Labels:          map[string]string{},
			OwnerReferences: []metav1.OwnerReference{},
		},
		Scope: &corev1.ObjectReference{
			APIVersion:      "v1",
			Kind:            "Pod",
			Namespace:       "pod-namespace",
			Name:            "privileged-pod",
			UID:             types.UID(uuid.NewString()),
			ResourceVersion: "1234",
		},
		Summary: wgpolicy.PolicyReportSummary{
			Pass:  0, // count of policies with requirements met
			Fail:  0, // count of policies with requirements not met
			Warn:  0, // not used for now
			Error: 0, // count of policies that couldn't be evaluated
			Skip:  0, // count of policies that were not selected for evaluation
		},
		Results: []*wgpolicy.PolicyReportResult{
			{
				Result:      statusFail,
				Description: "priviledged pod not allowed",
				Policy:      "pod-privileged",
			},
			{
				Result:      statusPass,
				Description: "",
				Policy:      "",
			},
			{
				Result:      statusFail,
				Description: "Invalid user",
				Policy:      "user-group-policy",
			},
		},
	}
	repeatInterval, err := time.ParseDuration(DEFAULT_REPEAT_INTERVAL_DURATION)
	require.NoError(t, err)
	expireInterval, err := time.ParseDuration(DEFAULT_EXPIRE_INTERVAL_DURATION)
	require.NoError(t, err)
	suseObsStore := NewSuseObsStore("apiKey", "https://suseobs.localhost", "urn:health:kubernetes:external-health", "cluster", repeatInterval, expireInterval)

	mockedRoundTripper := &MockRoundTripper{}
	suseObsStore.client = &http.Client{
		Transport: mockedRoundTripper,
	}

	mockedRoundTripper.On("RoundTrip",
		mock.MatchedBy(func(req *http.Request) bool {
			return req.Method == http.MethodPost &&
				req.Header.Get("Content-Type") == "application/json" &&
				req.Host == "suseobs.localhost" &&
				req.URL.Path == "/receiver/stsAgent/intake" &&
				req.URL.RawQuery == "api_key=apiKey" &&
				req.ContentLength > 0
		})).Return(&http.Response{
		StatusCode: http.StatusOK,
	}, nil)

	err = suseObsStore.CreateOrPatchPolicyReport(t.Context(), policyReport)
	require.NoError(t, err)

	mockedRoundTripper.AssertExpectations(t)
}

func TestSuseObsStartSnapshotPayload(t *testing.T) {
	repeatInterval, err := time.ParseDuration(DEFAULT_REPEAT_INTERVAL_DURATION)
	require.NoError(t, err)
	expireInterval, err := time.ParseDuration(DEFAULT_EXPIRE_INTERVAL_DURATION)
	require.NoError(t, err)
	suseObsStore := NewSuseObsStore("apiKey", "https://suseobs.localhost", "urn:health:kubernetes:external-health", "cluster", repeatInterval, expireInterval)
	expectedPayload := SuseObsJsonPayload{
		ApiKey:           "apiKey",
		InternalHostname: "suseobs.localhost",
		Events:           nil,
		Metrics:          []interface{}{},
		ServiceChecks:    []interface{}{},
		Topologies:       []interface{}{},
		Health: []SuseObsHealthCheck{{
			ConsistencyModel: DEFAULT_CONSISTENCY_MODEL,
			StartSnapshot: &SuseObsExpireConfiguration{
				RepeatInterval: 1800,
				ExpireInterval: 1800,
			},
			StopSnapshot: nil,
			Stream: SuseObsStream{
				Urn:         "urn:health:kubernetes:external-health",
				SubStreamId: "cluster",
			},
			CheckStates: []SuseObsCheckState{},
		}},
	}

	payload, err := suseObsStore.createStartSnapshotPayload()
	require.NoError(t, err)
	require.GreaterOrEqual(t, time.Now().Unix(), payload.CollectionTimestamp)
	expectedPayload.CollectionTimestamp = payload.CollectionTimestamp
	require.Equal(t, expectedPayload, *payload)

}

func TestSuseObsStopSnapshotPayload(t *testing.T) {
	repeatInterval, err := time.ParseDuration(DEFAULT_REPEAT_INTERVAL_DURATION)
	require.NoError(t, err)
	expireInterval, err := time.ParseDuration(DEFAULT_EXPIRE_INTERVAL_DURATION)
	require.NoError(t, err)
	suseObsStore := NewSuseObsStore("apiKey", "https://suseobs.localhost", "urn:health:kubernetes:external-health", "cluster", repeatInterval, expireInterval)
	expectedPayload := SuseObsJsonPayload{
		ApiKey:           "apiKey",
		InternalHostname: "suseobs.localhost",
		Events:           nil,
		Metrics:          []interface{}{},
		ServiceChecks:    []interface{}{},
		Topologies:       []interface{}{},
		Health: []SuseObsHealthCheck{{
			ConsistencyModel: DEFAULT_CONSISTENCY_MODEL,
			StartSnapshot:    nil,
			StopSnapshot:     &map[string]interface{}{},
			Stream: SuseObsStream{
				Urn:         "urn:health:kubernetes:external-health",
				SubStreamId: "cluster",
			},
			CheckStates: []SuseObsCheckState{},
		}},
	}

	payload, err := suseObsStore.createStopSnapshotPayload()
	require.NoError(t, err)
	require.GreaterOrEqual(t, time.Now().Unix(), payload.CollectionTimestamp)
	expectedPayload.CollectionTimestamp = payload.CollectionTimestamp
	require.Equal(t, expectedPayload, *payload)

}
