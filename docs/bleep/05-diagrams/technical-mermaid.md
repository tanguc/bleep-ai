# Bleep Technical Mermaid Diagram Pack

This file provides architecture-level Mermaid diagrams across different diagram types for planning, design review, and slide reuse.

## 1) System Context (flowchart)
```mermaid
flowchart LR
  U[Users and Internal Apps] --> W[Wrappers and SDKs]
  W --> G[Bleep Gateway in Customer Perimeter]
  G --> P[Policy Engine]
  G --> T[Transform Pipeline]
  T --> V[Token Vault]
  G --> L[Metadata Logs and Audit]
  G --> E[External LLM Providers]
  G --> M[Optional Local Models]
```

## 2) Component View (flowchart)
```mermaid
flowchart TB
  subgraph DataPlane[Data Plane]
    Ingress[API Ingress]
    Orchestrator[Request Orchestrator]
    Detect[Detectors]
    Transform[Redact/Tokenize]
    Route[Model Router]
    ResponseGuard[Response Guard]
  end

  subgraph ControlPlane[Control Plane]
    Policy[Policy Service]
    Admin[Admin UI/API]
    Config[Provider and Tenant Config]
  end

  Ingress --> Orchestrator --> Detect --> Transform --> Route --> ResponseGuard
  Policy --> Orchestrator
  Admin --> Policy
  Config --> Route
```

## 3) Request Sequence (sequenceDiagram)
```mermaid
sequenceDiagram
  participant App as App/CLI
  participant GW as Bleep Gateway
  participant PE as Policy Engine
  participant TP as Transform Pipeline
  participant LP as LLM Provider

  App->>GW: Request(messages, model)
  GW->>PE: Evaluate policy
  PE-->>GW: allow + transform plan
  GW->>TP: Detect and transform sensitive fields
  TP-->>GW: sanitized payload + token map ref
  GW->>LP: Forward transformed request
  LP-->>GW: Response stream
  GW-->>App: Response (+ optional reinjection)
```

## 4) Token Vault Data Model (erDiagram)
```mermaid
erDiagram
  TENANT ||--o{ TOKEN_MAP : owns
  TOKEN_MAP ||--o{ ACCESS_EVENT : records
  POLICY_VERSION ||--o{ ACCESS_EVENT : evaluated_by

  TENANT {
    string tenant_id
    string name
  }

  TOKEN_MAP {
    string token_id
    string tenant_id
    string encrypted_original
    string surrogate
    datetime expires_at
  }

  ACCESS_EVENT {
    string event_id
    string token_id
    string principal_id
    string decision
    datetime created_at
  }

  POLICY_VERSION {
    string version_id
    string tenant_id
    datetime published_at
  }
```

## 5) Policy Decision Lifecycle (stateDiagram-v2)
```mermaid
stateDiagram-v2
  [*] --> Received
  Received --> Classified
  Classified --> Allowed
  Classified --> Transformed
  Classified --> Blocked
  Transformed --> Routed
  Allowed --> Routed
  Routed --> Responded
  Blocked --> Responded
  Responded --> [*]
```

## 6) Failure and Recovery (stateDiagram-v2)
```mermaid
stateDiagram-v2
  [*] --> Healthy
  Healthy --> Degraded: Provider timeout spike
  Healthy --> PolicyUnsafe: Policy service unavailable
  Degraded --> Failover: Circuit breaker open
  Failover --> Healthy: Alternate provider stable
  PolicyUnsafe --> BlockMode: Fail-closed for sensitive classes
  BlockMode --> Recovery
  Recovery --> Healthy
```

## 7) Trust Boundaries (flowchart)
```mermaid
flowchart TB
  subgraph B1[Boundary 1: Client Zone]
    C1[Apps and CLIs]
  end

  subgraph B2[Boundary 2: Customer Perimeter]
    C2[Gateway]
    C3[Policy and Transform]
    C4[Token Vault and Logs]
  end

  subgraph B3[Boundary 3: External Provider Zone]
    C5[External LLM APIs]
  end

  C1 --> C2 --> C3 --> C5
  C3 --> C4
```

## 8) Deployment Topology (flowchart)
```mermaid
flowchart LR
  subgraph CustomerVPC[Customer VPC or On-Prem]
    LB[Load Balancer]
    GW1[Gateway Pod A]
    GW2[Gateway Pod B]
    Vault[(Token Vault Store)]
    Audit[(Audit Store)]
    Policy[(Policy Store)]
  end

  Apps --> LB --> GW1
  LB --> GW2
  GW1 --> Vault
  GW2 --> Vault
  GW1 --> Audit
  GW2 --> Audit
  GW1 --> Policy
  GW2 --> Policy
  GW1 --> Providers[(External Providers)]
  GW2 --> Providers
```

## 9) Alpha Rollout Plan (gantt)
```mermaid
gantt
  title Bleep Alpha v1 Rollout
  dateFormat  YYYY-MM-DD
  section Foundation
  Architecture baseline          :done, a1, 2026-03-01, 14d
  Policy template baseline       :active, a2, 2026-03-10, 21d
  section Pilot
  Pilot team onboarding          :a3, 2026-04-01, 21d
  Detector tuning and QA         :a4, 2026-04-10, 28d
  section Expansion
  Controlled multi-team rollout  :a5, 2026-05-10, 35d
  Enterprise packaging validation:a6, 2026-05-20, 30d
```

## 10) Team Interaction (journey)
```mermaid
journey
  title Bleep Cross-Functional Startup Workflow
  section Build
    Define policy baseline: 4: Product, Security, Engineering
    Ship gateway integration: 5: Engineering, Platform
  section Validate
    Run pilot and collect evidence: 4: Security, IT, CS
    Tune detection and policy rules: 3: Engineering, Security
  section Scale
    Convert pilot to paid tier: 4: Sales, Finance, Legal
    Expand to new teams: 5: IT, CS, Platform
```

