/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package opensandbox

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime/schema"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	cacheutils "github.com/openkruise/agents/pkg/cache/utils"
	managererrors "github.com/openkruise/agents/pkg/sandbox-manager/errors"
)

func TestResolveTemplateID(t *testing.T) {
	tests := []struct {
		name         string
		aliases      map[string]string
		imageURI     string
		wantTemplate string
		wantErr      bool
	}{
		{
			name:         "exact hit returns template",
			aliases:      map[string]string{"python:3.11": "python-tpl"},
			imageURI:     "python:3.11",
			wantTemplate: "python-tpl",
		},
		{
			name:    "miss returns ErrImageNotMapped",
			aliases: map[string]string{"python:3.11": "python-tpl"},
			// A different tag is a different image; Phase 1 does no
			// registry/tag normalization, so this must miss.
			imageURI: "python:3.12",
			wantErr:  true,
		},
		{
			name:     "empty image uri is a miss",
			aliases:  map[string]string{"python:3.11": "python-tpl"},
			imageURI: "",
			wantErr:  true,
		},
		{
			name:     "nil alias table is a miss",
			aliases:  nil,
			imageURI: "python:3.11",
			wantErr:  true,
		},
		{
			name:     "empty alias table is a miss",
			aliases:  map[string]string{},
			imageURI: "python:3.11",
			wantErr:  true,
		},
		{
			name:     "alias mapped to empty template is a miss",
			aliases:  map[string]string{"python:3.11": ""},
			imageURI: "python:3.11",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveTemplateID(tt.aliases, tt.imageURI)
			if tt.wantErr {
				require.Error(t, err)
				// The caller classifies this as 400 by type, not by message,
				// so the concrete type is part of the contract.
				var notMapped *ErrImageNotMapped
				require.ErrorAs(t, err, &notMapped)
				assert.Equal(t, tt.imageURI, notMapped.ImageURI)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantTemplate, got)
		})
	}
}

func TestMapState(t *testing.T) {
	tests := []struct {
		name        string
		agentsState string
		reason      string
		want        SandboxState
	}{
		{
			name:        "running maps to Running",
			agentsState: agentsv1alpha1.SandboxStateRunning,
			reason:      "RunningResourceClaimedAndReady",
			want:        SandboxStateRunning,
		},
		{
			name:        "claimed but not ready is surfaced as Running",
			agentsState: agentsv1alpha1.SandboxStateDead,
			reason:      "RunningResourceClaimedButNotReady",
			want:        SandboxStateRunning,
		},
		{
			name:        "paused maps to Paused",
			agentsState: agentsv1alpha1.SandboxStatePaused,
			reason:      "RunningResourceClaimedAndPaused",
			want:        SandboxStatePaused,
		},
		{
			name:        "creating maps to Pending",
			agentsState: agentsv1alpha1.SandboxStateCreating,
			reason:      agentsv1alpha1.SandboxStateReasonResourcePending,
			want:        SandboxStatePending,
		},
		{
			name:        "dead with terminal reason maps to Terminated",
			agentsState: agentsv1alpha1.SandboxStateDead,
			reason:      "ResourceTerminating",
			want:        SandboxStateTerminated,
		},
		{
			name:        "unknown state falls back to Running",
			agentsState: "some-future-state",
			reason:      "Whatever",
			want:        SandboxStateRunning,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, MapState(tt.agentsState, tt.reason))
		})
	}
}

func TestParseImageAlias(t *testing.T) {
	tests := []struct {
		name         string
		entry        string
		wantImage    string
		wantTemplate string
		wantErr      bool
	}{
		{name: "simple pair", entry: "python:3.11=python-tpl", wantImage: "python:3.11", wantTemplate: "python-tpl"},
		{name: "surrounding spaces are trimmed", entry: "  python:3.11 = python-tpl  ", wantImage: "python:3.11", wantTemplate: "python-tpl"},
		{name: "registry with port", entry: "registry.local:5000/app:v1=app-tpl", wantImage: "registry.local:5000/app:v1", wantTemplate: "app-tpl"},
		{name: "missing separator", entry: "python:3.11", wantErr: true},
		{name: "empty image uri", entry: "=python-tpl", wantErr: true},
		{name: "empty template id", entry: "python:3.11=", wantErr: true},
		{name: "empty entry", entry: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			image, template, err := ParseImageAlias(tt.entry)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantImage, image)
			assert.Equal(t, tt.wantTemplate, template)
		})
	}
}

func TestParseImageAliases(t *testing.T) {
	tests := []struct {
		name    string
		entries []string
		want    map[string]string
		wantErr bool
	}{
		{
			name:    "nil list yields nil map",
			entries: nil,
			want:    nil,
		},
		{
			name:    "empty list yields nil map",
			entries: []string{},
			want:    nil,
		},
		{
			name:    "single entry",
			entries: []string{"python:3.11=python-tpl"},
			want:    map[string]string{"python:3.11": "python-tpl"},
		},
		{
			name:    "multiple distinct entries",
			entries: []string{"python:3.11=python-tpl", "node:20=node-tpl"},
			want:    map[string]string{"python:3.11": "python-tpl", "node:20": "node-tpl"},
		},
		{
			name:    "duplicate image uri is rejected",
			entries: []string{"python:3.11=tpl-a", "python:3.11=tpl-b"},
			wantErr: true,
		},
		{
			name:    "malformed entry is rejected",
			entries: []string{"python:3.11=python-tpl", "bad-entry"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseImageAliases(tt.entries)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestMapStateReasonPhase exhaustively covers the agents (state, reason, phase)
// combinations produced by utils.GetSandboxState and asserts each maps to the
// intended OpenSandbox lifecycle state. The final cases assert an unmapped
// combination returns an error rather than silently degrading to Running.
func TestMapStateReasonPhase(t *testing.T) {
	tests := []struct {
		name    string
		state   string
		reason  string
		phase   string
		want    SandboxState
		wantErr bool
	}{
		{name: "creating is Pending", state: agentsv1alpha1.SandboxStateCreating, reason: agentsv1alpha1.SandboxStateReasonResourcePending, phase: string(agentsv1alpha1.SandboxPending), want: SandboxStatePending},
		{name: "pool not ready is Pending", state: agentsv1alpha1.SandboxStateCreating, reason: "ResourceControlledBySbsButNotReady", phase: string(agentsv1alpha1.SandboxPending), want: SandboxStatePending},
		{name: "available pool is Pending", state: agentsv1alpha1.SandboxStateAvailable, reason: "ResourceControlledBySbsAndReady", phase: string(agentsv1alpha1.SandboxRunning), want: SandboxStatePending},
		{name: "running is Running", state: agentsv1alpha1.SandboxStateRunning, reason: "RunningResourceClaimedAndReady", phase: string(agentsv1alpha1.SandboxRunning), want: SandboxStateRunning},
		{name: "pause accepted while running is Pausing", state: agentsv1alpha1.SandboxStatePaused, reason: reasonRunningClaimedAndPaused, phase: string(agentsv1alpha1.SandboxRunning), want: SandboxStatePausing},
		{name: "paused phase is Paused", state: agentsv1alpha1.SandboxStatePaused, reason: reasonNotRunningClaimed, phase: string(agentsv1alpha1.SandboxPaused), want: SandboxStatePaused},
		{name: "resuming phase is Resuming", state: agentsv1alpha1.SandboxStatePaused, reason: reasonNotRunningClaimed, phase: string(agentsv1alpha1.SandboxResuming), want: SandboxStateResuming},
		{name: "recycling phase is Stopping", state: agentsv1alpha1.SandboxStatePaused, reason: reasonNotRunningClaimed, phase: string(agentsv1alpha1.SandboxRecycling), want: SandboxStateStopping},
		{name: "upgrading phase is Running", state: agentsv1alpha1.SandboxStatePaused, reason: reasonNotRunningClaimed, phase: string(agentsv1alpha1.SandboxUpgrading), want: SandboxStateRunning},
		{name: "claimed but not ready is Running", state: agentsv1alpha1.SandboxStateDead, reason: reasonRunningClaimedButNotReady, phase: string(agentsv1alpha1.SandboxRunning), want: SandboxStateRunning},
		{name: "terminating is Stopping", state: agentsv1alpha1.SandboxStateDead, reason: reasonResourceTerminating, phase: string(agentsv1alpha1.SandboxTerminating), want: SandboxStateStopping},
		{name: "failed is Failed", state: agentsv1alpha1.SandboxStateDead, reason: reasonResourceFailed, phase: string(agentsv1alpha1.SandboxFailed), want: SandboxStateFailed},
		{name: "deleted is Terminated", state: agentsv1alpha1.SandboxStateDead, reason: reasonResourceDeleted, phase: string(agentsv1alpha1.SandboxTerminating), want: SandboxStateTerminated},
		{name: "succeeded is Terminated", state: agentsv1alpha1.SandboxStateDead, reason: reasonResourceSucceeded, phase: string(agentsv1alpha1.SandboxSucceeded), want: SandboxStateTerminated},
		{name: "shutdown time reached is Terminated", state: agentsv1alpha1.SandboxStateDead, reason: reasonShutdownTimeReached, phase: string(agentsv1alpha1.SandboxRunning), want: SandboxStateTerminated},
		{name: "unknown state is an error", state: "some-future-state", reason: "Whatever", phase: "Running", wantErr: true},
		{name: "unknown dead reason is an error", state: agentsv1alpha1.SandboxStateDead, reason: "SomeNewReason", phase: string(agentsv1alpha1.SandboxRunning), wantErr: true},
		{name: "unknown paused reason is an error", state: agentsv1alpha1.SandboxStatePaused, reason: "SomeNewReason", phase: string(agentsv1alpha1.SandboxPaused), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := mapStateReasonPhase(tt.state, tt.reason, tt.phase)
			if tt.wantErr {
				require.Error(t, err)
				assert.Empty(t, got)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestMapStateAgreesWithMapSandboxState guards against the create-path mapper
// (MapState) and the read-path mapper (mapStateReasonPhase) drifting apart on
// the states a freshly claimed sandbox can report.
func TestMapStateAgreesWithMapSandboxState(t *testing.T) {
	tests := []struct {
		name   string
		state  string
		reason string
		phase  string
	}{
		{name: "running", state: agentsv1alpha1.SandboxStateRunning, reason: "RunningResourceClaimedAndReady", phase: string(agentsv1alpha1.SandboxRunning)},
		{name: "claimed not ready", state: agentsv1alpha1.SandboxStateDead, reason: reasonRunningClaimedButNotReady, phase: string(agentsv1alpha1.SandboxRunning)},
		{name: "creating", state: agentsv1alpha1.SandboxStateCreating, reason: agentsv1alpha1.SandboxStateReasonResourcePending, phase: string(agentsv1alpha1.SandboxPending)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			full, err := mapStateReasonPhase(tt.state, tt.reason, tt.phase)
			require.NoError(t, err)
			assert.Equal(t, MapState(tt.state, tt.reason), full)
		})
	}
}

func TestMapLifecycleErrorToApiError(t *testing.T) {
	notFoundK8s := apierrors.NewNotFound(schema.GroupResource{Group: "apps.kruise.io", Resource: "sandboxes"}, "sbx-1")

	tests := []struct {
		name     string
		err      error
		wantCode int
	}{
		{name: "k8s not found maps to 404", err: notFoundK8s, wantCode: http.StatusNotFound},
		{name: "manager not found maps to 404", err: managererrors.NewError(managererrors.ErrorNotFound, "missing"), wantCode: http.StatusNotFound},
		{name: "bad request maps to 400", err: managererrors.NewError(managererrors.ErrorBadRequest, "bad"), wantCode: http.StatusBadRequest},
		{name: "conflict maps to 409", err: managererrors.NewError(managererrors.ErrorConflict, "conflict"), wantCode: http.StatusConflict},
		{name: "wait task conflict maps to 409", err: cacheutils.ErrWaitTaskConflict, wantCode: http.StatusConflict},
		{name: "quota exceeded maps to 403", err: managererrors.NewError(managererrors.ErrorQuotaExceeded, "quota"), wantCode: http.StatusForbidden},
		{name: "internal maps to 500", err: managererrors.NewError(managererrors.ErrorInternal, "boom"), wantCode: http.StatusInternalServerError},
		{name: "untyped error maps to 500", err: assert.AnError, wantCode: http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mapLifecycleErrorToApiError(tt.err)
			require.NotNil(t, got)
			assert.Equal(t, tt.wantCode, got.Code)
			assert.Equal(t, tt.err.Error(), got.Message)
		})
	}
}

func TestGetSandboxErrorCode(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		wantCode int
	}{
		{name: "not found is 404", err: managererrors.NewError(managererrors.ErrorNotFound, "missing"), wantCode: http.StatusNotFound},
		{name: "not allowed is 404 (anti-enumeration)", err: managererrors.NewError(managererrors.ErrorNotAllowed, "foreign"), wantCode: http.StatusNotFound},
		{name: "bad request state is 404 (anti-enumeration)", err: managererrors.NewError(managererrors.ErrorBadRequest, "wrong state"), wantCode: http.StatusNotFound},
		{name: "internal is 500", err: managererrors.NewError(managererrors.ErrorInternal, "cache outage"), wantCode: http.StatusInternalServerError},
		{name: "untyped is 404", err: assert.AnError, wantCode: http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantCode, getSandboxErrorCode(tt.err))
		})
	}
}
