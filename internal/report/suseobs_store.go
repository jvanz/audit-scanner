package report

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	wgpolicy "sigs.k8s.io/wg-policy-prototypes/policy-report/pkg/api/wgpolicyk8s.io/v1alpha2"
)

const DEFAULT_CONSISTENCY_MODEL = "REPEAT_STATES"
const DEFAULT_REPEAT_INTERVAL = "50"
const DEFAULT_EXPIRE_INTERVAL = "300"
const DEFAULT_HEALTH_CHECK_STATUS = "Deviating"

// SuseObsStore is a store for PolicyReport and ClusterPolicyReport.
type SuseObsStore struct {
	client           *http.Client
	apiKey           string
	internalHostname string
	urn              string
	cluster          string
}

type SuseObsExpireConfiguration struct {
	RepeatInterval string `json:"repeat_interval_s"`
	ExpireInterval string `json:"expiry_interval_s"`
}

type SuseObsStream struct {
	Urn string `json:"urn"`
}

type SuseObsCheckState struct {
	CheckStateId              string `json:"checkStateId"`
	Message                   string `json:"message"`
	Health                    string `json:"health"`
	TopologyElementIdentifier string `json:"topologyElementIdentifier"`
	Name                      string `json:"name"`
}

type SuseObsHealthCheck struct {
	ConsistencyModel string                     `json:"consistency_model"`
	Expire           SuseObsExpireConfiguration `json:"expire"`
	Stream           SuseObsStream              `json:"stream"`
	CheckStates      []SuseObsCheckState        `json:"check_states"`
}

type SuseObsJsonPayload struct {
	ApiKey              string               `json:"apiKey"`
	CollectionTimestamp int64                `json:"collection_timestamp"`
	InternalHostname    string               `json:"internalHostname"`
	Events              []interface{}        `json:"events"`
	Metrics             []interface{}        `json:"metrics"`
	ServiceChecks       []interface{}        `json:"service_checks"`
	Health              []SuseObsHealthCheck `json:"health"`
	Topologies          []interface{}        `json:"topoligies"`
}

// NewSuseObsStore creates a new SuseObsStore.
func NewSuseObsStore(apiKey, internalHostname, urn, cluster string) *SuseObsStore {
	return &SuseObsStore{
		client:           &http.Client{},
		apiKey:           apiKey,
		internalHostname: internalHostname,
		urn:              urn,
		cluster:          cluster,
	}
}

func (s *SuseObsStore) generateCheckStates(policyReport *wgpolicy.PolicyReport) []SuseObsCheckState {
	checkStates := []SuseObsCheckState{}
	for _, result := range policyReport.Results {
		if result.Result != "fail" {
			continue
		}
		checkState := SuseObsCheckState{
			CheckStateId:              uuid.NewString(), // FIXME: the NewString function can panic
			Message:                   result.Description,
			Health:                    DEFAULT_HEALTH_CHECK_STATUS,
			TopologyElementIdentifier: strings.ToLower("url:kubernetes:/" + s.cluster + ":" + policyReport.Scope.Kind + "/" + policyReport.Scope.Name),
			Name:                      result.Policy,
		}
		checkStates = append(checkStates, checkState)
	}
	return checkStates
}

func (s *SuseObsStore) generateCheckStatesFromClusterPolicyReport(policyReport *wgpolicy.ClusterPolicyReport) []SuseObsCheckState {
	checkStates := []SuseObsCheckState{}
	for _, result := range policyReport.Results {
		if result.Result != "fail" {
			continue
		}
		checkState := SuseObsCheckState{
			CheckStateId:              uuid.NewString(), // FIXME: the NewString function can panic
			Message:                   result.Description,
			Health:                    DEFAULT_HEALTH_CHECK_STATUS,
			TopologyElementIdentifier: strings.ToLower("url:kubernetes:/" + s.cluster + ":" + policyReport.Scope.Kind + "/" + policyReport.Scope.Name),
			Name:                      result.Policy,
		}
		checkStates = append(checkStates, checkState)
	}
	return checkStates
}

func (s *SuseObsStore) generateSuseObsJsonPayload(checkStates []SuseObsCheckState) (*SuseObsJsonPayload, error) {
	url, err := url.Parse(s.internalHostname)
	if err != nil {
		return nil, errors.New("failed to parse SUSE OBS URL")
	}
	payload := &SuseObsJsonPayload{
		ApiKey:              s.apiKey,
		InternalHostname:    url.Hostname(),
		CollectionTimestamp: time.Now().Unix(),
		Events:              []interface{}{},
		Metrics:             []interface{}{},
		ServiceChecks:       []interface{}{},
		Topologies:          []interface{}{},
		Health: []SuseObsHealthCheck{{
			ConsistencyModel: DEFAULT_CONSISTENCY_MODEL,
			Expire: SuseObsExpireConfiguration{
				RepeatInterval: DEFAULT_REPEAT_INTERVAL,
				ExpireInterval: DEFAULT_EXPIRE_INTERVAL,
			},
			Stream: SuseObsStream{
				Urn: s.urn,
			},
			CheckStates: checkStates,
		}},
	}
	return payload, nil
}

func (s *SuseObsStore) convertPolicyReportIntoSuseObsJsonPayload(policyReport *wgpolicy.PolicyReport) (*SuseObsJsonPayload, error) {
	return s.generateSuseObsJsonPayload(s.generateCheckStates(policyReport))
}

func (s *SuseObsStore) convertClusterPolicyReportIntoSuseObsJsonPayload(policyReport *wgpolicy.ClusterPolicyReport) (*SuseObsJsonPayload, error) {
	return s.generateSuseObsJsonPayload(s.generateCheckStatesFromClusterPolicyReport(policyReport))
}

// CreateOrPatchPolicyReport creates or patches a PolicyReport.
func (s *SuseObsStore) CreateOrPatchPolicyReport(ctx context.Context, policyReport *wgpolicy.PolicyReport) error {
	payload, err := s.convertPolicyReportIntoSuseObsJsonPayload(policyReport)
	if err != nil {
		return err
	}
	return s.sendRequest(payload)
}

func (s *SuseObsStore) DeleteOldPolicyReports(ctx context.Context, scanRunID, namespace string) error {
	// No need to delete SUSE Obs will remove the check states after the expiry interval
	return nil
}

// CreateOrPatchClusterPolicyReport creates or patches a ClusterPolicyReport.
func (s *SuseObsStore) CreateOrPatchClusterPolicyReport(ctx context.Context, clusterPolicyReport *wgpolicy.ClusterPolicyReport) error {
	payload, err := s.convertClusterPolicyReportIntoSuseObsJsonPayload(clusterPolicyReport)
	if err != nil {
		return err
	}
	return s.sendRequest(payload)
}

func (s *SuseObsStore) DeleteOldClusterPolicyReports(ctx context.Context, scanRunID string) error {
	// No need to delete SUSE Obs will remove the check states after the expiry interval
	return nil
}

func (s *SuseObsStore) sendRequest(payload *SuseObsJsonPayload) error {
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return errors.New("failed to marshal SUSE OBS payload")
	}
	url := s.internalHostname + "/receiver/stsAgent/intake?api_key="
	log.Debug().Dict("dict", zerolog.Dict()).
		Str("SUSE Obs URL", url).
		Msg("Sending SUSE OBS healch check request")

	response, err := s.client.Post(url+s.apiKey, "application/json", bytes.NewReader(jsonPayload))
	if err != nil {
		return errors.New("failed to send SUSE OBS payload")
	}
	if response.StatusCode != http.StatusOK {
		return errors.New("SUSE Obs returned an error")
	}
	return nil

}
