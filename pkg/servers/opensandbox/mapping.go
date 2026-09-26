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
	"errors"
	"fmt"
	"net/http"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	agentsv1alpha1 "github.com/openkruise/agents/api/v1alpha1"
	cacheutils "github.com/openkruise/agents/pkg/cache/utils"
	managererrors "github.com/openkruise/agents/pkg/sandbox-manager/errors"
	"github.com/openkruise/agents/pkg/sandbox-manager/infra"
	"github.com/openkruise/agents/pkg/servers/web"
)

// ErrImageNotMapped reports a missing transitional image alias. Automatic
// virtual-template preparation is still required for image create compatibility.
type ErrImageNotMapped struct {
	ImageURI string
}

func (e *ErrImageNotMapped) Error() string {
	return fmt.Sprintf("image %q is not mapped to any SandboxTemplate; add %s=<template-id> to the %s environment variable", e.ImageURI, e.ImageURI, EnvImageAliases)
}

// ResolveTemplateID looks up the agents SandboxTemplate name that backs the
// given OpenSandbox image URI. The alias table is injected at startup
// (the OPENSANDBOX_IMAGE_ALIASES environment variable) and is read-only at
// request time. Lookup is
// exact-string: no normalization, no registry/tag inference. A miss returns an
// error wrapping *ErrImageNotMapped so the caller can classify it as 500 with
// errors.As instead of matching on the message.
//
// The error is returned as the interface type (not the concrete pointer) so a
// successful lookup yields a true nil error: returning a nil *ErrImageNotMapped
// through an error-typed variable would produce a non-nil interface and break
// `err != nil` checks at the call site.
func ResolveTemplateID(aliases map[string]string, imageURI string) (string, error) {
	if imageURI == "" {
		return "", &ErrImageNotMapped{ImageURI: imageURI}
	}
	if templateID, ok := aliases[imageURI]; ok && templateID != "" {
		return templateID, nil
	}
	return "", &ErrImageNotMapped{ImageURI: imageURI}
}

// MapState translates an agents sandbox state (plus the reason string that
// accompanies the "dead" state) into the OpenSandbox lifecycle vocabulary.
//
// A claimed instance that is not ready remains Pending. Native E2B state
// conventions must not turn a missing readiness observation into Running on
// the OpenSandbox API. Unknown backend states also remain Pending, retaining
// the reason for diagnosis until a recognized observation arrives.
func MapState(agentsState, reason string) SandboxState {
	if agentsState == agentsv1alpha1.SandboxStateDead && reason == "RunningResourceClaimedButNotReady" {
		return SandboxStatePending
	}
	switch agentsState {
	case agentsv1alpha1.SandboxStateRunning:
		return SandboxStateRunning
	case agentsv1alpha1.SandboxStatePaused:
		return SandboxStatePaused
	case agentsv1alpha1.SandboxStateCreating:
		return SandboxStatePending
	case agentsv1alpha1.SandboxStateDead:
		return SandboxStateTerminated
	default:
		return SandboxStatePending
	}
}

// EnvImageAliases is the environment variable carrying the comma-separated
// image alias table ("image_uri=template_id,..."). It is typically injected
// from a ConfigMap via envFrom and is read once at startup; there is no
// dynamic refresh, so changing it requires a pod restart.
const EnvImageAliases = "OPENSANDBOX_IMAGE_ALIASES"

// SplitImageAliasesEnv splits an EnvImageAliases value into individual
// "image_uri=template_id" entries. Entries are trimmed and empty items are
// dropped so a trailing comma or a formatted multi-line ConfigMap value stays
// parsable; malformed entries are left for ParseImageAliases to reject.
func SplitImageAliasesEnv(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	entries := make([]string, 0, len(parts))
	for _, part := range parts {
		if part = strings.TrimSpace(part); part != "" {
			entries = append(entries, part)
		}
	}
	return entries
}

// Reason strings reported by utils.GetSandboxState alongside SandboxState*.
// Only SandboxStateReasonResourcePending is exported upstream; the remaining
// values are hard-coded string literals in utils.GetSandboxState, mirrored here
// so the OpenSandbox state mapping can branch on them without repeating bare
// literals at each call site. Keep in sync with pkg/utils/utils.go.
const (
	reasonResourceDeleted           = "ResourceDeleted"
	reasonShutdownTimeReached       = "ShutdownTimeReached"
	reasonResourceSucceeded         = "ResourceSucceeded"
	reasonResourceFailed            = "ResourceFailed"
	reasonResourceTerminating       = "ResourceTerminating"
	reasonRunningClaimedButNotReady = "RunningResourceClaimedButNotReady"
	reasonRunningClaimedAndPaused   = "RunningResourceClaimedAndPaused"
	reasonNotRunningClaimed         = "NotRunningResourceClaimed"
)

// MapSandboxState projects an agents sandbox into the full OpenSandbox
// lifecycle vocabulary (specs/sandbox-lifecycle.yml `SandboxState`: Pending,
// Running, Pausing, Paused, Resuming, Stopping, Terminated, Failed).
//
// It is the describe/list counterpart of MapState (the create-path subset).
// MapState only ever needs Running/Pending for a freshly claimed sandbox, so
// it stays a pure (state, reason) function; MapSandboxState additionally reads
// Phase() to separate the transient states agents collapses together:
//
//   - Spec.Paused while Phase==Running (reason RunningResourceClaimedAndPaused)
//     is a pause that has been accepted but not completed → Pausing.
//   - Phase==Resuming (reason NotRunningClaimed) → Resuming; Phase==Paused →
//     Paused; Phase==Recycling → Stopping; Phase==Upgrading → Running.
//   - dead + RunningResourceClaimedButNotReady remains Pending, consistent
//     with the create response until readiness is observed.
//   - dead + ResourceTerminating → Stopping; ResourceFailed → Failed;
//     ResourceDeleted / ResourceSucceeded / ShutdownTimeReached → Terminated.
//
// An unrecognized (state, reason, phase) combination returns an error rather
// than silently degrading to Running, so a future agents-side state surfaces as
// a 500 at the API boundary instead of masquerading as a live sandbox.
func MapSandboxState(sbx infra.Sandbox) (SandboxState, error) {
	state, reason := sbx.GetState()
	return mapStateReasonPhase(state, reason, sbx.Phase())
}

func mapStateReasonPhase(state, reason, phase string) (SandboxState, error) {
	switch state {
	case agentsv1alpha1.SandboxStateCreating:
		// Provisioning, or a pool sandbox not yet ready. Either way the
		// sandbox is not live from the caller's perspective.
		return SandboxStatePending, nil
	case agentsv1alpha1.SandboxStateAvailable:
		// A pool sandbox that is ready but unclaimed. Not user-visible in
		// practice (list/describe are owner-scoped), mapped to Pending so it
		// never reads as a live claimed sandbox.
		return SandboxStatePending, nil
	case agentsv1alpha1.SandboxStateRunning:
		return SandboxStateRunning, nil
	case agentsv1alpha1.SandboxStatePaused:
		switch reason {
		case reasonRunningClaimedAndPaused:
			// Spec.Paused set while Phase is still Running: pause accepted,
			// checkpoint not yet complete.
			return SandboxStatePausing, nil
		case reasonNotRunningClaimed:
			switch phase {
			case string(agentsv1alpha1.SandboxResuming):
				return SandboxStateResuming, nil
			case string(agentsv1alpha1.SandboxRecycling):
				return SandboxStateStopping, nil
			case string(agentsv1alpha1.SandboxUpgrading):
				return SandboxStateRunning, nil
			default:
				// Phase==Paused (and any other non-running claimed phase).
				return SandboxStatePaused, nil
			}
		}
	case agentsv1alpha1.SandboxStateDead:
		switch reason {
		case reasonRunningClaimedButNotReady:
			return SandboxStatePending, nil
		case reasonResourceTerminating:
			return SandboxStateStopping, nil
		case reasonResourceFailed:
			return SandboxStateFailed, nil
		case reasonResourceDeleted, reasonResourceSucceeded, reasonShutdownTimeReached:
			return SandboxStateTerminated, nil
		}
	}
	return "", fmt.Errorf("opensandbox: unmapped agents sandbox state %q (reason %q, phase %q)", state, reason, phase)
}

// mapLifecycleErrorToApiError converts a manager/infra error from a
// sandbox-scoped lifecycle operation (pause/resume/delete/renew) into an
// ApiError. It is deliberately separate from create.go's
// mapInfraErrorToApiError: the create path maps ErrorNotFound to 400 (a missing
// template is a bad request), whereas the lifecycle routes map it to 404 (a
// missing sandbox is not found), matching the OpenSandbox spec's per-route
// response codes.
//
// Mapping (specs/sandbox-lifecycle.yml lifecycle routes admit 400/401/403/
// 404/409/500):
//   - k8s NotFound, ErrorNotFound → 404
//   - ErrorBadRequest → 400
//   - ErrorConflict, wait-task conflict → 409
//   - ErrorQuotaExceeded → 403
//   - ErrorInternal, ErrorUnknown, untyped → 500
//
// 401 is produced by the CheckApiKey middleware, and sandbox-load failures are
// classified by getSandboxErrorCode (anti-enumeration), so neither appears here.
// 429 is not emitted: agents has no request-rate limiter (compatibility limit).
func mapLifecycleErrorToApiError(err error) *web.ApiError {
	if apierrors.IsNotFound(err) {
		return &web.ApiError{Code: http.StatusNotFound, Message: err.Error()}
	}
	if errors.Is(err, cacheutils.ErrWaitTaskConflict) {
		return &web.ApiError{Code: http.StatusConflict, Message: err.Error()}
	}
	switch managererrors.GetErrCode(err) {
	case managererrors.ErrorNotFound:
		return &web.ApiError{Code: http.StatusNotFound, Message: err.Error()}
	case managererrors.ErrorBadRequest:
		return &web.ApiError{Code: http.StatusBadRequest, Message: err.Error()}
	case managererrors.ErrorConflict:
		return &web.ApiError{Code: http.StatusConflict, Message: err.Error()}
	case managererrors.ErrorQuotaExceeded:
		return &web.ApiError{Code: http.StatusForbidden, Message: err.Error()}
	default:
		return &web.ApiError{Code: http.StatusInternalServerError, Message: err.Error()}
	}
}

// ParseImageAlias parses a single alias entry of the form
// "image_uri=template_id". It returns an error when the entry is malformed so
// startup fails loudly instead of registering a half-parsed alias.
func ParseImageAlias(entry string) (imageURI, templateID string, err error) {
	imageURI, templateID, found := strings.Cut(entry, "=")
	if !found {
		return "", "", fmt.Errorf("invalid image alias %q: expected image_uri=template_id", entry)
	}
	imageURI = strings.TrimSpace(imageURI)
	templateID = strings.TrimSpace(templateID)
	if imageURI == "" || templateID == "" {
		return "", "", fmt.Errorf("invalid image alias %q: image_uri and template_id must both be non-empty", entry)
	}
	return imageURI, templateID, nil
}

// ParseImageAliases parses a list of alias entries (see SplitImageAliasesEnv) into a
// read-only map. Duplicate image URIs are rejected: an operator typo that
// silently overwrites an earlier alias is worse than a startup failure.
func ParseImageAliases(entries []string) (map[string]string, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	aliases := make(map[string]string, len(entries))
	for _, entry := range entries {
		imageURI, templateID, err := ParseImageAlias(entry)
		if err != nil {
			return nil, err
		}
		if existing, ok := aliases[imageURI]; ok {
			return nil, fmt.Errorf("duplicate image alias for %q: already mapped to %q, cannot remap to %q", imageURI, existing, templateID)
		}
		aliases[imageURI] = templateID
	}
	return aliases, nil
}
