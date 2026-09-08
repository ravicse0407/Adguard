from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator


class RiskLevel(str, Enum):
    GREEN = "GREEN"
    AMBER = "AMBER"
    RED = "RED"


class Decision(str, Enum):
    ALLOW = "ALLOW"
    LOGGED = "LOGGED"
    BLOCKED = "BLOCKED"
    APPROVED = "APPROVED"
    DENIED = "DENIED"


class ToolCallPayload(BaseModel):
    agent: Optional[str] = Field(default=None, description="Name or ID of the AI agent")
    agent_id: Optional[str] = Field(default=None, description="Alternative ID of the AI agent")
    action: str = Field(..., min_length=1, description="Tool or function being called")
    target: Optional[str] = Field(default="", description="Target resource, file, database, or endpoint")
    arguments: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Key-value arguments for tool call")
    reason: Optional[str] = Field(default="", description="Optional context or reason for tool call")

    @model_validator(mode="after")
    def check_agent_present(self) -> "ToolCallPayload":
        name = (self.agent or self.agent_id or "").strip()
        if not name:
            raise ValueError("Field 'agent' or 'agent_id' is required and cannot be empty")
        self.agent = name
        return self

    def get_agent_name(self) -> str:
        return self.agent or self.agent_id or ""


class InterceptResponse(BaseModel):
    request_id: str
    timestamp: str
    agent: str
    action: str
    target: str
    arguments: Dict[str, Any]
    risk_level: RiskLevel
    decision: Decision
    reason: str
    approval_required: bool
    prompt_injection_detected: bool
    prompt_injection_reason: Optional[str] = None
    risk_score: Optional[int] = None
    threat_detected: Optional[bool] = None
    risk_breakdown: Optional[Dict[str, Any]] = None
    signals: Optional[List[str]] = None
    pipeline_timings: Optional[Dict[str, int]] = None
    explainability: Optional[Dict[str, Any]] = None
    dynamic_risk_level: Optional[str] = None
    risk_factors: Optional[List[Dict[str, Any]]] = None
    indicators: Optional[Dict[str, bool]] = None
    dynamic_explanation: Optional[str] = None



class AuditLogEntry(BaseModel):
    id: int
    request_id: str
    timestamp: str
    agent: str
    action: str
    target: str
    arguments: Dict[str, Any]
    risk_level: str
    decision: str
    reason: str
    prompt_injection_detected: bool
    prompt_injection_reason: Optional[str] = None
    approval_required: bool
    approved_by: Optional[str] = None
    resolved_at: Optional[str] = None


class PendingApprovalItem(BaseModel):
    id: int
    request_id: str
    timestamp: str
    agent: str
    action: str
    target: str
    arguments: Dict[str, Any]
    risk_level: str
    decision: str
    reason: str
    prompt_injection_detected: bool
    prompt_injection_reason: Optional[str] = None


class ResolutionResponse(BaseModel):
    success: bool
    request_id: str
    decision: Decision
    approved_by: str
    resolved_at: str
    message: str


class AgentProfile(BaseModel):
    name: str
    risk_tier: str  # LOW, MEDIUM, HIGH, CRITICAL
    risk_score: int  # 0-100
    trust_level: str  # HIGH, MODERATE, RESTRICTED, UNTRUSTED
    total_actions: int
    allowed_count: int
    blocked_count: int
    pending_count: int
    allowed_tools: List[str]
    blocked_tools: List[str]
    recent_actions: List[Dict[str, Any]]
    policy_violations: int


class ThreatIntelItem(BaseModel):
    id: str
    title: str
    category: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    count: int
    trend: str
    last_detected: Optional[str] = None
    description: str
    mitigation: Optional[str] = None


class SecurityPosture(BaseModel):
    overall_score: int
    runtime_protection: int
    prompt_defense: int
    tool_security: int
    policy_coverage: int
    audit_integrity: int
    recommendations_count: int
    recommendations: List[Dict[str, Any]]


class StatsResponse(BaseModel):
    total_actions: int
    approved_count: int
    logged_count: int
    blocked_count: int
    pending_count: int
    denied_count: int
    prompt_injections_detected: int
    security_score: int
    system_status: str
    agents_protected: int = 4
    risk_distribution: Dict[str, int] = Field(default_factory=lambda: {"LOW": 68, "MEDIUM": 21, "HIGH": 8, "CRITICAL": 3})
    threat_intel_counts: Dict[str, int] = Field(default_factory=dict)


class IncidentStatus(str, Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    CONTAINED = "CONTAINED"
    RESOLVED = "RESOLVED"


class IncidentSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class Incident(BaseModel):
    incident_id: str
    title: str
    severity: IncidentSeverity
    status: IncidentStatus
    agent: str
    created_at: str
    updated_at: str
    summary: str
    request_id: Optional[str] = None
    action: Optional[str] = None
    target: Optional[str] = None
    assigned_to: Optional[str] = "SecOps Lead"
    triage_notes: Optional[str] = ""
    evidence: Optional[Dict[str, Any]] = Field(default_factory=dict)
    risk_score: Optional[int] = 85
    detection_reason: Optional[str] = None


class IncidentCreate(BaseModel):
    title: str
    severity: IncidentSeverity = IncidentSeverity.HIGH
    agent: str
    summary: str
    request_id: Optional[str] = None
    action: Optional[str] = None
    target: Optional[str] = None
    triage_notes: Optional[str] = ""
    risk_score: Optional[int] = 85
    detection_reason: Optional[str] = None
    evidence: Optional[Dict[str, Any]] = Field(default_factory=dict)


class IncidentStatusUpdate(BaseModel):
    status: IncidentStatus
    assigned_to: Optional[str] = None
    triage_notes: Optional[str] = None


class IncidentActionRequest(BaseModel):
    action: str  # investigate, contain, resolve
    operator: Optional[str] = "SecOps Lead"
    notes: Optional[str] = ""
    quarantine_agent: Optional[bool] = False


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # agent, tool, target, action, decision
    trust_level: Optional[str] = None
    risk_score: Optional[int] = None
    decision: Optional[str] = None
    status: Optional[str] = None
    meta: Optional[Dict[str, Any]] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    label: Optional[str] = None
    decision: Optional[str] = None
    risk_level: Optional[str] = None


class SecurityGraphResponse(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    stats: Dict[str, Any]


class BehavioralAnalyticsResponse(BaseModel):
    agents: List[Dict[str, Any]]
    risk_trend: List[Dict[str, Any]]
    suspicious_trend: List[Dict[str, Any]]
    top_targets: List[Dict[str, Any]]
    dangerous_tools: List[Dict[str, Any]]
    prompt_injection_frequency: Dict[str, Any]
    anomaly_summary: Dict[str, Any]


class AgentGovernance(BaseModel):
    agent: str
    status: str = "ACTIVE"  # ACTIVE, ISOLATED, MONITOR_ONLY
    isolation_reason: Optional[str] = None
    isolated_at: Optional[str] = None
    trust_level: str = "MODERATE"
    custom_allowed_tools: List[str] = Field(default_factory=list)
    custom_blocked_tools: List[str] = Field(default_factory=list)
    max_daily_calls: int = 1000
    anomaly_score: int = 0


class IsolateAgentRequest(BaseModel):
    reason: str = "Manual security isolation by operator"
    action_taken: str = "QUARANTINE"


class AutonomousResponseRule(BaseModel):
    rule_id: str
    name: str
    trigger: str
    action: str
    enabled: bool = True
    cooldown_seconds: int = 60
    last_triggered: Optional[str] = None
    trigger_count: int = 0


class ExecuteResponseRequest(BaseModel):
    rule_id: str
    target_agent: Optional[str] = None
    notes: Optional[str] = None


class CopilotQueryRequest(BaseModel):
    query: str
    role: Optional[str] = "SecOps Engineer"


class CopilotQueryResponse(BaseModel):
    query: str
    answer: str
    confidence: float = 0.95
    sources: List[str] = Field(default_factory=list)
    suggested_actions: List[str] = Field(default_factory=list)


class PolicyRecommendation(BaseModel):
    rec_id: str
    agent: str
    title: str
    description: str
    impact: str
    rule_spec: Dict[str, Any]
    status: str = "PENDING"  # PENDING, APPLIED, DISMISSED


class AlertConfig(BaseModel):
    slack_webhook: Optional[str] = ""
    email_recipients: List[str] = Field(default_factory=lambda: ["security-ops@enterprise.internal"])
    pagerduty_key: Optional[str] = ""
    min_severity: str = "HIGH"
    enabled: bool = True

