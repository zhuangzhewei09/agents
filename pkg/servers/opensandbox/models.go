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

// Package opensandbox implements the OpenSandbox API adapter alongside the
// native E2B API, sharing SandboxManager and API-key storage. Create and the
// existing list/describe/delete/pause/resume/renew routes are consolidated here.
// Full create compatibility and endpoint integration remain in progress; the
// proposal records the fixed contract baseline and remaining execution gaps.
//
// Layering: this package sits in the API layer (pkg/servers/**). It depends on
// pkg/sandbox-manager (Manager) and pkg/servers/e2b/{keys,models} (shared auth
// types). It does not import pkg/servers/e2b itself, pkg/features, or any
// infra implementation subpackage.
package opensandbox

import "encoding/json"

// HeaderOpenSandboxAPIKey is the authentication header defined by the
// OpenSandbox lifecycle spec. It is translated to the same KeyStorage lookup
// used by the E2B `X-API-Key` header (issue #690: "reuse keys.KeyStorage").
const HeaderOpenSandboxAPIKey = "OPEN-SANDBOX-API-KEY" // #nosec G101 -- header name, not a credential

// SandboxState is the shared lifecycle vocabulary for create and read responses.
type SandboxState string

const (
	SandboxStatePending    SandboxState = "Pending"
	SandboxStateRunning    SandboxState = "Running"
	SandboxStatePausing    SandboxState = "Pausing"
	SandboxStatePaused     SandboxState = "Paused"
	SandboxStateResuming   SandboxState = "Resuming"
	SandboxStateStopping   SandboxState = "Stopping"
	SandboxStateTerminated SandboxState = "Terminated"
	SandboxStateFailed     SandboxState = "Failed"
)

// Image identifies the container image a sandbox is created from. Phase 1
// resolves URI to an agents SandboxTemplate via a static alias table injected
// at startup; the formal "virtual template" direction (per-image auto-create
// or reuse of a SandboxSet) is tracked in issue #690.
type Image struct {
	URI string `json:"uri"`
}

// Platform mirrors the OpenSandbox top-level `platform` (PlatformSpec) field,
// which the spec defines as independent from `image`. Phase 1 parses it for
// forward compatibility but does not propagate it to the backend.
type Platform struct {
	OS   string `json:"os,omitempty"`
	Arch string `json:"arch,omitempty"`
}

// ResourceLimits mirrors the OpenSandbox `resourceLimits` field. Phase 1
// parses it for forward compatibility but does not propagate it to the
// backend; CPU/memory shaping stays whatever the resolved SandboxTemplate
// already declares.
type ResourceLimits struct {
	CPU    string `json:"cpu,omitempty"`
	Memory string `json:"memory,omitempty"`
}

// NetworkPolicy mirrors the OpenSandbox `networkPolicy` field. Phase 1 parses
// it as raw JSON so an unexpected shape is rejected explicitly instead of
// silently dropped, but does not propagate it to the backend.
type NetworkPolicy struct {
	DefaultAction string            `json:"defaultAction,omitempty"`
	Egress        []json.RawMessage `json:"egress,omitempty"`
}

// LifecycleHooks mirrors the OpenSandbox `lifecycle` field. Phase 1 parses it
// as raw JSON for forward compatibility but does not propagate it.
type LifecycleHooks struct {
	PreStart *json.RawMessage  `json:"preStart,omitempty"`
	Periodic []json.RawMessage `json:"periodic,omitempty"`
}

// CreateSandboxRequest is the Phase 1 subset of the OpenSandbox
// `CreateSandboxRequest` schema. Fields outside the Phase 1 scope are still
// decoded (so an unexpected shape surfaces as a parse error rather than being
// silently dropped) but are not propagated to the backend. Each ignored field
// is declared as a compatibility limit in the proposal.
type CreateSandboxRequest struct {
	// Image is the startup source for Phase 1. Exactly one of Image or
	// SnapshotID must be provided; Phase 1 rejects SnapshotID with 400.
	Image *Image `json:"image,omitempty"`
	// SnapshotID restore is not supported in Phase 1 and is rejected with 400.
	SnapshotID string `json:"snapshotId,omitempty"`
	// Entrypoint is parsed but not propagated to the sandbox spec in Phase 1.
	// It is echoed back in the create response because the OpenSandbox
	// response schema marks it required ("copied from the creation request").
	Entrypoint []string `json:"entrypoint,omitempty"`
	// Platform is the top-level platform constraint (PlatformSpec), parsed but
	// not propagated in Phase 1.
	Platform *Platform `json:"platform,omitempty"`
	// Timeout is the sandbox lifetime in seconds. Omitted/null disables
	// automatic expiration; a supplied value must be at least 60 seconds.
	Timeout *int64 `json:"timeout,omitempty"`
	// Env are environment variables injected into the sandbox runtime via
	// InitRuntime. The wire name is `env` per the OpenSandbox schema.
	Env map[string]string `json:"env,omitempty"`
	// Metadata is persisted as sandbox annotations and echoed back in the
	// response. Keys must be qualified Kubernetes annotation keys.
	Metadata map[string]string `json:"metadata,omitempty"`
	// ResourceLimits is parsed but not propagated in Phase 1.
	ResourceLimits *ResourceLimits `json:"resourceLimits,omitempty"`
	// NetworkPolicy is parsed but not propagated in Phase 1.
	NetworkPolicy *NetworkPolicy `json:"networkPolicy,omitempty"`
	// SecureAccess is parsed but not propagated in Phase 1.
	SecureAccess *bool `json:"secureAccess,omitempty"`
	// Lifecycle hooks are parsed but not propagated in Phase 1.
	Lifecycle *LifecycleHooks `json:"lifecycle,omitempty"`
}

// SandboxStatus mirrors the OpenSandbox `status` object on a sandbox
// resource. Phase 1 emits State and Reason; Message is reserved for later
// phases (describe/list) where the backend surfaces a human-readable
// explanation.
type SandboxStatus struct {
	State   SandboxState `json:"state"`
	Reason  string       `json:"reason,omitempty"`
	Message string       `json:"message,omitempty"`
}

// CreateSandboxResponse is the Phase 1 response body for `POST /v1/sandboxes`.
// It mirrors the OpenSandbox `CreateSandboxResponse` schema: the sandbox is
// returned synchronously with `status.state: "Running"` after provisioning
// completes. The schema marks `id`, `status`, `createdAt`, and `entrypoint`
// required, so those keys are always serialized (never omitempty): the
// generated SDKs pop them unconditionally and fail on a missing key. Other
// startup-source details (image, resourceLimits) and `updatedAt` are
// intentionally omitted per the upstream spec note ("Use GET
// /sandboxes/{sandboxId} to retrieve the complete sandbox information").
type CreateSandboxResponse struct {
	ID     string        `json:"id"`
	Status SandboxStatus `json:"status"`
	// Entrypoint is echoed from the creation request, per the upstream spec
	// ("copied from the creation request"). Phase 1 does not propagate it to
	// the sandbox spec; the echo exists for response-schema compliance.
	Entrypoint []string          `json:"entrypoint"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	ExpiresAt  string            `json:"expiresAt,omitempty"`
	// CreatedAt is schema-required, so it is never empty: it falls back to
	// the sandbox creation timestamp (then to now) when the claim-time
	// annotation is unreadable. See convertToOpenSandboxResponse.
	CreatedAt string `json:"createdAt"`
}

// SandboxResponse is the response body for the sandbox-scoped read routes
// (`GET /v1/sandboxes/{sandboxId}` and each item of `GET /v1/sandboxes`). It
// mirrors the OpenSandbox `Sandbox` schema, whose required keys are `id`,
// `status`, `createdAt`, and `entrypoint`; those are always serialized (never
// omitempty) so the generated SDKs can pop them unconditionally.
//
// Compatibility limits (Phase 2):
//   - `entrypoint` is always an empty list: the create path echoes the request
//     entrypoint but does not persist it, so it cannot be recovered on read.
//   - `image`, `snapshotId`, `platform`, `extensions`, and `allocation` are
//     omitted: agents sandboxes are template-backed, and the OpenSandbox
//     startup-source model has no agents counterpart yet (tracked by the
//     virtual-template direction in issue #690).
type SandboxResponse struct {
	ID         string            `json:"id"`
	Status     SandboxStatus     `json:"status"`
	Entrypoint []string          `json:"entrypoint"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	ExpiresAt  string            `json:"expiresAt,omitempty"`
	CreatedAt  string            `json:"createdAt"`
}

// PaginationInfo mirrors the OpenSandbox `PaginationInfo` schema. Every field
// is required, so the struct is always fully populated (no omitempty).
type PaginationInfo struct {
	Page        int  `json:"page"`
	PageSize    int  `json:"pageSize"`
	TotalItems  int  `json:"totalItems"`
	TotalPages  int  `json:"totalPages"`
	HasNextPage bool `json:"hasNextPage"`
}

// ListSandboxesResponse is the response body for `GET /v1/sandboxes`. It
// mirrors the OpenSandbox `ListSandboxesResponse` schema: both `items` and
// `pagination` are required. `Items` is always non-nil so it serializes as
// `[]` rather than `null` for an empty result set.
type ListSandboxesResponse struct {
	Items      []SandboxResponse `json:"items"`
	Pagination PaginationInfo    `json:"pagination"`
}

// RenewSandboxExpirationRequest is the request body for
// `POST /v1/sandboxes/{sandboxId}/renew-expiration`. It mirrors the OpenSandbox
// `RenewSandboxExpirationRequest` schema: `expiresAt` is a required RFC3339
// timestamp that must be in the future and after the current expiration.
type RenewSandboxExpirationRequest struct {
	ExpiresAt string `json:"expiresAt"`
}

// RenewSandboxExpirationResponse is the response body for the renew route. It
// mirrors the OpenSandbox `RenewSandboxExpirationResponse` schema, whose only
// required field is the updated `expiresAt`.
type RenewSandboxExpirationResponse struct {
	ExpiresAt string `json:"expiresAt"`
}
