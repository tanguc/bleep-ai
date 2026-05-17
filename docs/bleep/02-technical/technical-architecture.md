# Bleep Technical Documentation Pack (Architecture Level)

## 1. Document Scope
This pack defines the target architecture for Bleep as a privacy-preserving inference gateway and policy control plane for enterprise LLM traffic. It is implementation-agnostic and intended for:
- Architecture/design review
- Security and privacy review
- Alpha planning and definition-of-done alignment

Out of scope:
- Implementation code
- Vendor-specific IaC modules
- UI wireframes

## 2. System Context
### 2.1 Problem Statement
Organizations need to route prompts/responses to multiple AI providers while preventing sensitive data leakage, enforcing policy, and preserving observability without exposing raw content to non-authorized systems.

### 2.2 System Goals
- Provide a single API-compatible lane to multiple model providers
- Enforce pre- and post-inference privacy/policy controls
- Isolate and protect secrets and tokens via vault-backed indirection
- Offer deterministic auditability and compliance evidence
- Maintain high availability and low added latency

### 2.3 Actors
- Application clients (internal services, agent frameworks, end-user apps)
- Security admins (policy and key owners)
- Platform operators (SRE, infra)
- Compliance/audit stakeholders
- External model providers and enterprise-hosted models

### 2.4 External Systems
- Identity provider (OIDC/SAML)
- KMS/HSM
- Secret manager/token vault backend
- SIEM/log analytics
- Metrics/tracing backend
- Data classification/DLP services (optional)
- LLM providers (OpenAI-compatible and others via adapters)

## 3. High-Level Components
### 3.1 Edge/API Gateway
- Terminates TLS/mTLS
- Authenticates caller identity
- Performs tenant routing and rate limiting
- Exposes API compatibility surfaces

### 3.2 Request Orchestrator
- Normalizes request shape
- Resolves model routing policy
- Invokes privacy transform pipeline
- Calls provider adapter
- Applies response policies and returns transformed output

### 3.3 Provider Adapter Layer
- Provider-specific protocol translation
- Retry/circuit handling per provider
- Capability negotiation (streaming, tool call schema differences, function calling mode)

### 3.4 Privacy Transform Pipeline
- Prompt/content inspection
- Redaction/tokenization/pseudonymization based on policy
- Optional reversible token vault operations
- Metadata tagging for audit and restoration controls

### 3.5 Token Vault Service
- Stores mappings between original values and surrogate tokens
- Supports scoped detokenization rights
- Enforces TTL, purpose binding, and tenant isolation

### 3.6 Policy Engine
- Central policy evaluation and decision point
- Attribute-based access control and content policy
- Pre-request and post-response enforcement hooks

### 3.7 Key Management Layer
- Envelope encryption orchestration
- Key lifecycle orchestration with KMS/HSM
- Key use attestation and rotation metadata

### 3.8 Observability & Audit Plane
- Structured logs, traces, metrics
- Security events and immutable audit trails
- Policy decision logs (input metadata, rules matched, action)

### 3.9 Control Plane
- Policy management and rollout
- Provider configuration, model allowlists
- Tenant config, quota and SLO policy

### 3.10 Data Stores
- Policy store (versioned)
- Vault mapping store
- Operational metadata store
- Audit/event store (immutable retention-oriented)

## 4. API Compatibility Surfaces
### 4.1 Northbound Client API
- Default: OpenAI-compatible REST surface for `chat/completions`, `responses`, embeddings, and moderation-like flows
- Streaming support with SSE-compatible framing
- Backward-compatible versioned endpoint strategy (`/v1`, `/v1alpha`)

### 4.2 Behavioral Compatibility
- Preserve common request/response fields and error semantics
- Return deterministic compatibility errors when unsupported provider features are requested
- Capability discovery endpoint to expose model/tool/streaming support matrix

### 4.3 Southbound Provider Interfaces
- Native adapters per provider/model host
- Fallback adapter behavior when provider-specific features are absent
- Unified failure taxonomy (auth error, quota, transient provider, policy deny)

### 4.4 Control Plane API
- Policy CRUD/versioning
- Tenant and routing config
- Key and vault lifecycle operations (metadata only; secret material never exposed)

## 5. Privacy Transform Pipeline
### 5.1 Pipeline Stages (Request)
1. Content classification
2. Policy-driven transform plan generation
3. Transform execution: redact, mask, hash, tokenize, pseudonymize
4. Residual risk check
5. Forward transformed payload

### 5.2 Pipeline Stages (Response)
1. Response inspection and policy check
2. Optional detokenization for authorized callers/use-cases
3. Safety/egress filtering
4. Return response with transformation metadata headers

### 5.3 Transformation Modes
- Irreversible redaction: strongest privacy, lowest utility
- Reversible tokenization: balanced privacy and downstream utility
- Format-preserving pseudonymization: preserves schema and analytic value

### 5.4 Determinism and Traceability
- Every transform action produces a signed audit event
- Correlate request and response transforms through immutable request ID
- No raw secret content in standard logs

## 6. Token Vault Model
### 6.1 Data Model
- Token record: `{tenant_id, token_id, surrogate_value, encrypted_original_ref, transform_type, scope, ttl, created_at}`
- Access record: `{principal, purpose, policy_version, access_time, decision}`

### 6.2 Access Control
- ABAC with least-privilege scopes
- Purpose-of-use binding (e.g., support case, fraud review)
- Just-in-time detokenization approval path for sensitive classes

### 6.3 Lifecycle
- Create on transform
- Read on authorized detokenization
- Rotate/re-tokenize for long-lived records
- Expire and hard-delete by policy or legal retention windows

### 6.4 Isolation
- Strong tenant partitioning (logical + cryptographic separation)
- Optional dedicated vault per regulated tenant

## 7. Policy Engine
### 7.1 Policy Types
- Identity and tenant policy
- Data handling policy (PII/PHI/PCI and custom labels)
- Model routing/allowlist policy
- Safety and output policy
- Rate, quota, and abuse policy

### 7.2 Evaluation Model
- Ordered policy layers: global -> tenant -> application -> request context
- Deny-overrides with explicit exception mechanism
- Versioned policy snapshots for replayability and audits

### 7.3 Execution Points
- Pre-ingress (authn/authz, coarse route)
- Pre-provider (data transforms and model eligibility)
- Post-provider (content and detokenization controls)
- Egress (response release or redact/deny)

### 7.4 Change Management
- Staged rollout (dry-run, canary, enforce)
- Policy impact simulation against replay datasets
- Mandatory review gates for high-risk policies

## 8. Deployment Topologies
### 8.1 Topology A: Centralized Shared Service
- One Bleep control/data plane serving many teams
- Best for platform standardization and operational efficiency
- Requires strong tenant segmentation and quota governance

### 8.2 Topology B: Regional Shared Service
- Per-region Bleep deployment for data residency and latency
- Shared control plane with regional policy/data boundaries

### 8.3 Topology C: Dedicated Per-Business Unit
- Isolated deployment per BU/regulatory domain
- Strongest blast-radius isolation, highest operational cost

### 8.4 Topology D: Hybrid Edge + Core
- Lightweight edge policy checks near workloads
- Core orchestrator/vault in central secure zone
- Useful when low latency and strict egress controls coexist

## 9. Trust Boundaries
### 9.1 Boundary Map
- Boundary 1: Client -> Bleep edge
- Boundary 2: Edge -> internal control/data plane
- Boundary 3: Bleep -> external model providers
- Boundary 4: Bleep -> KMS/vault/secret backends
- Boundary 5: Bleep -> observability and SIEM sinks

### 9.2 Boundary Controls
- mTLS for service-to-service paths
- Workload identity (SPIFFE/SPIRE or equivalent)
- Network segmentation and egress allowlists
- Signed requests between critical internal components

## 10. Key Management
### 10.1 Key Hierarchy
- Root keys in HSM/KMS
- Service-level data encryption keys via envelope encryption
- Tenant-scoped keys for vault payload references

### 10.2 Rotation Strategy
- Scheduled rotation with overlap windows
- Emergency rotation playbook for compromise events
- Crypto-agility plan (algorithm/key length migration path)

### 10.3 Access and Governance
- Split duties: key admins vs service operators
- Key access via short-lived credentials only
- Full key usage audit and anomaly alerts

## 11. Observability
### 11.1 Metrics
- Request volume, p50/p95/p99 latency
- Policy deny rate and transform rate by class
- Provider error rates and fallback frequency
- Vault lookup/detokenization latency

### 11.2 Logging
- Structured logs with sensitive-field suppression
- Decision logs with policy version and rule IDs
- Security logs for privilege escalations and unusual data access

### 11.3 Tracing
- End-to-end trace IDs across edge, transforms, provider adapter, vault
- Span attributes for model/provider/route decision

### 11.4 Alerting
- SLO burn-rate alerts
- Security anomaly alerts (spike in detokenization/denies/exfil patterns)
- Dependency degradation alerts (provider/KMS/vault failures)

## 12. Reliability and SLOs
### 12.1 Target SLOs (Alpha Baseline)
- Availability: 99.9% monthly for gateway endpoints
- Added median latency overhead (Bleep only): <=120 ms
- Added p95 latency overhead: <=300 ms
- Policy decision success: >=99.99%
- Audit event delivery durability: >=99.999%

### 12.2 Reliability Patterns
- Multi-AZ stateless services
- Queue-backed audit/event buffering
- Provider failover with circuit breakers
- Graceful degradation modes when optional controls fail

### 12.3 Failure Modes and Degradation
- Provider outage: route to backup model/provider if policy allows
- Vault outage: fail-closed for detokenization, fail-open/closed for non-sensitive flows based on policy mode
- Policy engine outage: cached signed policies with bounded TTL

## 13. Scalability Concerns
### 13.1 Throughput Drivers
- Concurrent streaming sessions
- Transform complexity per token
- Vault read/write amplification
- Policy evaluation cardinality

### 13.2 Scale Patterns
- Horizontal scaling for stateless edge/orchestrator/policy evaluators
- Partitioned vault storage by tenant + hash ranges
- Async pipelines for non-blocking audit exports
- Provider connection pooling and adaptive concurrency limits

### 13.3 Hotspots
- Large prompt inspection cost
- Burst traffic from agentic workflows
- Shared provider quotas causing backpressure

## 14. Threat Model
### 14.1 Assets
- Raw prompts/responses
- Vault mappings
- API credentials/provider keys
- Policy definitions and exception rules
- Audit trails

### 14.2 Adversaries
- External attacker
- Compromised client workload
- Malicious/overprivileged insider
- Supply-chain compromised dependency
- Rogue provider-side access or leakage

### 14.3 Key Threats
- Data exfiltration through prompt/response channels
- Prompt injection causing policy bypass attempts
- Token vault abuse via privilege escalation
- Key compromise and decryption of sensitive payload refs
- Logging pipeline leakage of sensitive data
- Denial-of-service against policy/vault dependencies

### 14.4 Mitigations
- Strict egress policies and response filtering
- Defense-in-depth policy checks (pre/post)
- Fine-grained ABAC + JIT approvals for detokenization
- Envelope encryption and rapid key rotation capability
- Sensitive-data-safe logging defaults
- Rate limits, WAF, DDoS controls, and adaptive throttling

## 15. Limitations (Alpha)
- Imperfect detection/classification for novel sensitive patterns
- Additional latency overhead in deep transform modes
- Feature parity gaps across model providers
- Limited support for multimodal transforms in early phases
- False positives/negatives in policy outcomes until tuning stabilizes
- Higher operational complexity if per-tenant dedicated vaults are enabled

## 16. Testing Strategy
### 16.1 Architecture Test Layers
- Contract tests for northbound API compatibility
- Adapter conformance tests per provider
- Policy regression suites using labeled prompt/response corpora
- Vault security tests (authz, TTL expiry, isolation)
- Chaos/failure-injection tests for provider, vault, KMS outages

### 16.2 Non-Functional Validation
- Load tests for sustained and burst concurrency
- Soak tests for memory/connection stability
- Latency budget tracking per pipeline stage
- Security tests: penetration, abuse-case, and red-team scenarios

### 16.3 Pre-Release Gates
- All critical threat scenarios mapped to tested controls
- SLO canary validation in production-like environment
- Audit completeness verification under peak load

## 17. Alpha Definition of Done (DoD)
- API compatibility: OpenAI-compatible core endpoints stable for target clients
- Privacy controls: request and response transform pipeline active for selected data classes
- Token vault: scoped detokenization and TTL expiry enforced
- Policy engine: versioned policies with dry-run and enforce modes
- Security: baseline threat mitigations validated for high-risk scenarios
- Reliability: meets alpha SLO baselines for 30-day observation window
- Observability: traceable request lifecycle and policy/audit logs available
- Operations: documented runbooks for top failure/incident scenarios

## 18. Phased Roadmap
### Phase 0: Foundation (Weeks 0-4)
- Define canonical API compatibility profile
- Stand up baseline gateway, policy skeleton, audit pipeline
- Establish key and secret governance model

### Phase 1: Privacy Core Alpha (Weeks 5-10)
- Enable request transform pipeline and initial token vault
- Integrate primary and fallback model providers
- Implement policy dry-run and enforcement controls

### Phase 2: Reliability and Multi-Region Beta (Weeks 11-18)
- Regional topology and failover hardening
- Advanced observability and SLO burn-rate automation
- Expanded threat mitigations and red-team validation

### Phase 3: GA Readiness (Weeks 19-28)
- Full control-plane UX and policy lifecycle automation
- Broader provider capability compatibility
- Compliance evidence packaging and external audit support

## 19. Explicit Design Tradeoffs
### 19.1 Privacy Strength vs Latency
- Stronger inspection and reversible transforms improve governance but increase p95 latency.
- Tradeoff decision: support tiered policy modes (strict, balanced, low-latency).

### 19.2 Fail-Closed vs Availability
- Fail-closed protects sensitive flows but may reduce uptime during dependency outages.
- Tradeoff decision: classify routes by risk and choose fail behavior per route class.

### 19.3 Centralized vs Dedicated Deployments
- Centralized reduces cost and improves consistency; dedicated improves isolation.
- Tradeoff decision: default centralized with dedicated option for regulated tenants.

### 19.4 Compatibility vs Provider Optimization
- Strict uniform API abstraction can hide provider-specific performance features.
- Tradeoff decision: keep default compatibility surface plus explicit opt-in extension namespace.

### 19.5 Comprehensive Logging vs Data Minimization
- Rich logs aid debugging/compliance but increase leakage risk.
- Tradeoff decision: log decisions/metadata by default, raw content only via break-glass controls.

## 20. Recommended Defaults
- API profile: OpenAI-compatible `/v1` with explicit capability discovery endpoint
- Policy mode: `balanced` (sensitive classes tokenized, non-sensitive pass-through)
- Detokenization: disabled by default; enable per application scope + purpose binding
- Failure behavior: fail-closed for sensitive classes, fail-open for non-sensitive low-risk routes
- Deployment: regional shared topology for production; centralized shared for early alpha
- Keys: envelope encryption with tenant-scoped DEKs and 90-day rotation baseline
- Logging: metadata-first logs, content-suppressed, immutable audit stream mandatory
- SLO baseline: 99.9% availability and <=300 ms p95 added overhead
- Rollout model: dry-run -> canary -> enforce for all major policy changes

## 21. Open Decisions for Architecture Review
- Which data classes are considered sensitive at launch?
- What percentage of traffic requires reversible tokenization?
- Which provider-specific features justify extension APIs?
- Which tenants require dedicated vault or dedicated deployment at alpha?
- What is the acceptable fail-open scope under provider/vault incidents?

