package report

import (
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

func TestSuseObsPayloadCreation(t *testing.T) {
	suseObsStore := NewSuseObsStore("apiKey", "suseobs.localhost", "urn:health:kubernetes:external-health", "cluster")
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

	payload := suseObsStore.convertPolicyReportIntoSuseObsJsonPayload(policyReport)
	expectedPayload := SuseObsJsonPayload{
		ApiKey:           "apiKey",
		InternalHostname: "suseobs.localhost",
		Events:           []interface{}{},
		Metrics:          []interface{}{},
		ServiceChecks:    []interface{}{},
		Topologies:       []interface{}{},
		Health: []SuseObsHealthCheck{{
			ConsistencyModel: DEFAULT_CONSISTENCY_MODEL,
			Expire: SuseObsExpireConfiguration{
				RepeatInterval: DEFAULT_REPEAT_INTERVAL,
				ExpireInterval: DEFAULT_EXPIRE_INTERVAL,
			},
			Stream: SuseObsStream{
				Urn: "urn:health:kubernetes:external-health",
			},
			CheckStates: []SuseObsCheckState{
				{
					CheckStateId:              "",
					Message:                   "priviledged pod not allowed",
					Health:                    DEFAULT_HEALTH_CHECK_STATUS,
					TopologyElementIdentifier: "url:kubernetes:/cluster:pod/privileged-pod",
					Name:                      "pod-privileged",
				},

				{
					CheckStateId:              "",
					Message:                   "Invalid user",
					Health:                    DEFAULT_HEALTH_CHECK_STATUS,
					TopologyElementIdentifier: "url:kubernetes:/cluster:pod/privileged-pod",
					Name:                      "user-group-policy",
				},
			},
		}},
	}
	require.GreaterOrEqual(t, time.Now().Unix(), payload.CollectionTimestamp)
	expectedPayload.CollectionTimestamp = payload.CollectionTimestamp
	require.Equal(t, len(expectedPayload.Health[0].CheckStates), len(payload.Health[0].CheckStates))
	for i, result := range payload.Health[0].CheckStates {
		require.NotEmpty(t, result.CheckStateId)
		expectedPayload.Health[0].CheckStates[i].CheckStateId = result.CheckStateId
	}
	require.Equal(t, expectedPayload, payload)
	bytes, err := json.Marshal(payload)
	require.NoError(t, err)
	fmt.Println(string(bytes))
}
