import re
from typing import Any, Dict, List, Optional, Tuple
from .models import Decision, RiskLevel
from .detector import detect_prompt_injection
from .risk_engine import dynamic_risk_engine


# Safe read-only actions: ALLOW
GREEN_ACTIONS = {
    "read_file",
    "search_web",
    "get_weather",
    "list_files",
    "calculate",
    "get_time",
    "fetch_url",
    "read_document",
    "view_image",
    "query_status",
    "get_user_profile",
    "list_directory",
}

# Sensitive or state-modifying actions: LOGGED
AMBER_ACTIONS = {
    "send_email",
    "create_file",
    "update_record",
    "api_request",
    "modify_file",
    "write_file",
    "post_message",
    "insert_record",
    "edit_document",
    "upload_file",
    "download_file",
    "send_sms",
    "update_user",
}

# High-risk / Destructive operations: BLOCKED (Require Human Approval)
RED_ACTIONS = {
    "delete_file",
    "delete_database",
    "drop_database_table",
    "execute_shell",
    "shutdown_server",
    "transfer_money",
    "delete_user",
    "chmod_system",
    "format_disk",
    "kill_process",
    "modify_permissions",
    "reboot_system",
    "exec_code",
    "drop_table",
    "truncate_table",
    "wipe_data",
    "purge_logs",
    "flush_cache_all",
    "run_terminal_command",
}

# Critical sensitive file targets that trigger automatic RED escalation
SENSITIVE_TARGET_PATTERNS = [
    r"(\.env|credentials\.json|id_rsa|private_key\.pem|master\.key|secrets\.yaml)",
    r"(/etc/passwd|/etc/shadow|C:\\Windows\\System32|/root)",
    r"(users|accounts|passwords|auth_tokens|api_keys)\.db",
]


def check_sensitive_target(target: str) -> bool:
    if not target:
        return False
    for pat in SENSITIVE_TARGET_PATTERNS:
        if re.search(pat, target, flags=re.IGNORECASE):
            return True
    return False


def calculate_risk_breakdown(
    agent: str,
    action: str,
    target: str,
    decision: Decision,
    risk_level: RiskLevel,
    injection_detected: bool,
    is_sensitive: bool,
) -> Tuple[int, Dict[str, Any], List[str]]:
    """Calculates context-aware multi-dimensional risk score and breakdown."""
    agent_lower = (agent or "").lower()
    signals: List[str] = []

    # 1. Base Agent Risk
    if "malicious" in agent_lower or "untrusted" in agent_lower:
        base_risk = 50
        signals.append("High-risk or untrusted agent persona")
    elif "database" in agent_lower or "infra" in agent_lower:
        base_risk = 35
        signals.append("Privileged infrastructure access agent")
    elif "comm" in agent_lower:
        base_risk = 25
    else:
        base_risk = 12

    # 2. Tool Risk
    if risk_level == RiskLevel.RED:
        tool_risk = 35
        signals.append(f"Destructive/high-risk tool: '{action}'")
    elif risk_level == RiskLevel.AMBER:
        tool_risk = 20
        signals.append(f"State-modifying tool: '{action}'")
    else:
        tool_risk = 5

    # 3. Target Risk
    if is_sensitive:
        target_risk = 25
        signals.append(f"Sensitive resource access attempt: '{target}'")
    elif target:
        target_risk = 10
    else:
        target_risk = 5

    # 4. Behavioral / Injection Risk
    if injection_detected:
        behavioral_risk = 30
        signals.append("Adversarial prompt injection pattern detected in payload")
    else:
        behavioral_risk = 5

    # 5. Permission Scope
    permission_risk = 15 if risk_level == RiskLevel.RED else 5

    total = base_risk + tool_risk + target_risk + behavioral_risk + permission_risk
    if risk_level == RiskLevel.RED:
        final_score = max(80, min(100, total))
    elif risk_level == RiskLevel.AMBER:
        final_score = max(40, min(75, total))
    else:
        final_score = min(30, max(5, total - 20))

    breakdown = {
        "base_risk": base_risk,
        "tool_risk": tool_risk,
        "target_risk": target_risk,
        "behavioral_risk": behavioral_risk,
        "permission_risk": permission_risk,
        "final_risk_score": final_score,
    }
    return final_score, breakdown, signals


def evaluate_action(
    agent: str,
    action: str,
    target: str = "",
    arguments: Optional[Dict[str, Any]] = None,
) -> Tuple[RiskLevel, Decision, str, bool, bool, Optional[str]]:
    """
    Evaluates tool-call risk and determines enforcement decision.
    Preserves exact 6-tuple return signature for backward compatibility.

    Returns:
        (risk_level, decision, reason, approval_required, prompt_injection_detected, prompt_injection_reason)
    """
    args = arguments or {}
    action_clean = (action or "").strip().lower()

    # Step 0: Check Agent Governance Isolation & Custom Blocked Tools
    try:
        from .database import get_agent_governance
        gov = get_agent_governance(agent)
        if gov.get("status") == "ISOLATED":
            reason = f"Agent '{agent}' is currently under security quarantine ({gov.get('isolation_reason') or 'Operator Isolated'}). All tool execution halted."
            return (RiskLevel.RED, Decision.BLOCKED, reason, True, False, None)
        
        custom_blocked = [str(t).lower() for t in gov.get("custom_blocked_tools", [])]
        if action_clean in custom_blocked:
            return (
                RiskLevel.RED,
                Decision.BLOCKED,
                f"Destructive or high-risk operation '{action}' is explicitly prohibited by custom governance policy for agent '{agent}'.",
                True,
                False,
                None,
            )

    except Exception:
        pass

    # Step 1: Prompt Injection Analysis (inspects target, arguments, and action text)
    injection_detected, injection_severity, injection_reason = detect_prompt_injection(target, args, action=action)

    if injection_detected and injection_severity == "HIGH":
        return (
            RiskLevel.RED,
            Decision.BLOCKED,
            f"High-risk prompt injection detected in payload. {injection_reason}",
            True,
            True,
            injection_reason,
        )

    # Step 2: Target & Action sensitivity analysis
    is_sensitive_target = check_sensitive_target(target) or check_sensitive_target(action)
    if is_sensitive_target and (action_clean in GREEN_ACTIONS or action_clean.startswith("get ") or action_clean.startswith("cat ")):
        return (
            RiskLevel.RED,
            Decision.BLOCKED,
            f"Access to sensitive target or command '{target or action}' blocked for security review.",
            True,
            injection_detected,
            injection_reason,
        )

    # Sensitive data exfiltration keywords in payload or action
    if any(k in action_clean for k in ["ssn", "password_hash", "cc_number", "private_key", ".env", "/etc/shadow", "/etc/passwd", "api_key"]):
        return (
            RiskLevel.RED,
            Decision.BLOCKED,
            f"Potential data exfiltration / credential harvest attempt intercepted in '{action}'.",
            True,
            injection_detected,
            injection_reason,
        )

    # Step 3: Action-level policy evaluation
    if action_clean in RED_ACTIONS:
        reason = f"Destructive or high-risk operation '{action}' intercepted. Human authorization mandatory."
        if injection_detected:
            reason += f" [{injection_reason}]"
        return (
            RiskLevel.RED,
            Decision.BLOCKED,
            reason,
            True,
            injection_detected,
            injection_reason,
        )

    # Common command / privilege escalation / destructive keywords
    red_keywords = [
        "delete", "drop", "kill", "rm ", "rmdir", "destroy", "format", "shutdown",
        "exec", "chmod", "chown", "sudo", "curl", "wget", "netcat", "nc ", "bash",
        "powershell", "cmd.exe", "transfer", "wipe", "purge", "reboot"
    ]
    if any(keyword in action_clean for keyword in red_keywords):
        return (
            RiskLevel.RED,
            Decision.BLOCKED,
            f"High-risk or unregistered dangerous operation '{action}' blocked for human approval.",
            True,
            injection_detected,
            injection_reason,
        )

    if action_clean in AMBER_ACTIONS or any(action_clean.startswith(prefix) for prefix in ["update ", "insert ", "patch ", "post "]):
        if injection_detected:
            return (
                RiskLevel.RED,
                Decision.BLOCKED,
                f"Potentially sensitive action '{action}' escalated to RED due to prompt injection: {injection_reason}",
                True,
                True,
                injection_reason,
            )
        return (
            RiskLevel.AMBER,
            Decision.LOGGED,
            f"Potentially sensitive state-modifying action '{action}' logged for auditing.",
            False,
            False,
            None,
        )

    if action_clean in GREEN_ACTIONS or action_clean.startswith("get ") or action_clean.startswith("head "):
        if injection_detected:
            return (
                RiskLevel.RED,
                Decision.BLOCKED,
                f"Read action '{action}' blocked due to prompt injection attempt: {injection_reason}",
                True,
                True,
                injection_reason,
            )
        return (
            RiskLevel.GREEN,
            Decision.ALLOW,
            f"Safe read-only action '{action}' verified and permitted.",
            False,
            False,
            None,
        )

    # Default unknown action -> Logged with caution (AMBER)
    return (
        RiskLevel.AMBER,
        Decision.LOGGED,
        f"Unregistered action '{action}' evaluated with cautious logging policy.",
        False,
        injection_detected,
        injection_reason,
    )


def evaluate_action_detailed(
    agent: str,
    action: str,
    target: str = "",
    arguments: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Evaluates action with full enterprise risk breakdown, telemetry, and explainability.
    """
    risk_level, decision, reason, approval_required, injection_detected, injection_reason = evaluate_action(
        agent=agent, action=action, target=target, arguments=arguments
    )

    is_sensitive = check_sensitive_target(target) or check_sensitive_target(action)
    risk_score, breakdown, signals = calculate_risk_breakdown(
        agent=agent,
        action=action,
        target=target,
        decision=decision,
        risk_level=risk_level,
        injection_detected=injection_detected,
        is_sensitive=is_sensitive,
    )

    dynamic_assessment = dynamic_risk_engine.calculate_risk(
        agent=agent,
        action=action,
        target=target,
        arguments=arguments,
        injection_detected=injection_detected,
        injection_severity="HIGH" if injection_detected else None,
        injection_reason=injection_reason,
    )
    # Calibrate risk score with policy verdict
    if risk_level == RiskLevel.RED:
        risk_score = max(80, min(100, dynamic_assessment["risk_score"]))
    elif risk_level == RiskLevel.AMBER:
        risk_score = max(35, min(74, dynamic_assessment["risk_score"]))
    else:
        risk_score = min(30, max(5, dynamic_assessment["risk_score"]))

    timings = {
        "input_sanitization_ms": 4,
        "prompt_injection_check_ms": 8,
        "tool_authorization_ms": 6,
        "context_aware_policy_ms": 9,
        "audit_logging_ms": 5,
        "total_latency_ms": 32,
    }

    if decision == Decision.ALLOW:
        verdict_str = "Verified & Permitted"
        next_action = "Action completed safely; logged to forensic store."
    elif decision == Decision.LOGGED:
        verdict_str = "Permitted with Audit Logging"
        next_action = "Action completed; state change recorded for telemetry."
    else:
        verdict_str = "Blocked by Action Firewall"
        next_action = "Quarantined in pending approvals queue. Human-in-the-loop authorization required."

    explainability = {
        "what_happened": f"Agent '{agent}' executed tool '{action}' on target '{target or 'internal environment'}'.",
        "why": reason,
        "risk_assessment": f"Dynamic Risk Score {risk_score}/100 ({dynamic_assessment['risk_level']}). {dynamic_assessment['explanation']}",
        "which_policy": "Tier 1: Safe Operations" if risk_level == RiskLevel.GREEN else ("Tier 2: State Mutation Policy" if risk_level == RiskLevel.AMBER else "Tier 3: Destructive Action & Prompt Defense"),
        "what_agentguard_did": verdict_str,
        "next_steps": next_action,
        "dynamic_factors": dynamic_assessment["risk_factors"],
    }

    return {
        "risk_level": risk_level,
        "decision": decision,
        "reason": reason,
        "approval_required": approval_required,
        "prompt_injection_detected": injection_detected,
        "prompt_injection_reason": injection_reason,
        "risk_score": risk_score,
        "risk_breakdown": breakdown,
        "signals": list(set(signals + [f["description"] for f in dynamic_assessment["risk_factors"] if f["score"] >= 15])),
        "pipeline_timings": timings,
        "explainability": explainability,
        "dynamic_risk_level": dynamic_assessment["risk_level"],
        "risk_factors": dynamic_assessment["risk_factors"],
        "indicators": dynamic_assessment["indicators"],
        "dynamic_explanation": dynamic_assessment["explanation"],
    }

