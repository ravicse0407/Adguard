"""
Dynamic Risk Engine for AgentGuard
Evaluates multi-vector real-time risk scores (0–100), risk levels (LOW, MEDIUM, HIGH, CRITICAL),
and granular factor breakdown across 9 threat vectors while integrating with the policy firewall.
"""

import re
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path

from .models import Decision, RiskLevel
from .detector import detect_prompt_injection

# Sensitivity sets and regexes
SENSITIVE_TARGET_PATTERNS = [
    r"(\.env|credentials\.json|id_rsa|private_key\.pem|master\.key|secrets\.yaml)",
    r"(/etc/passwd|/etc/shadow|C:\\Windows\\System32|/root)",
    r"(users|accounts|passwords|auth_tokens|api_keys)\.db",
    r"(prod_customers|user_sessions|payment_records|cardholder_data)",
]

EXFILTRATION_INDICATORS = [
    r"(ssn|cc_number|password_hash|private_key|api_key|token|auth_token)",
    r"(curl|wget|nc|ncat|netcat|invoke-webrequest|fetch|http://|https://)",
    r"(base64\s+-d|xxd\s+-r|scp\s+|sftp\s+|rsync\s+|transfer_to|dump_to)",
    r"(\.attacker\.|\.evil\.|\.exfil\.|\.ngrok\.io|webhook\.site|[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}:[0-9]+)",
]

PRIVILEGE_ESCALATION_INDICATORS = [
    r"(chmod(_system)?|chown|chgrp|sudo\b|su\s+-|runas|setuid)",
    r"(bash\s+-i|sh\s+-i|/bin/sh|/bin/bash|cmd\.exe|powershell\.exe)",
    r"(/dev/tcp/|mkfifo|mknod|pipe|pty\.spawn|socket\.connect)",
    r"(root\b|administrator\b|system32|kernel|se_debug_privilege)",
]

KNOWN_GREEN_TOOLS = {
    "read_file", "search_web", "get_weather", "list_files", "calculate",
    "get_time", "fetch_url", "read_document", "view_image", "query_status",
    "get_user_profile", "list_directory", "head_file", "cat_public"
}

KNOWN_AMBER_TOOLS = {
    "send_email", "create_file", "update_record", "api_request", "modify_file",
    "write_file", "post_message", "insert_record", "edit_document", "upload_file",
    "download_file", "send_sms", "update_user", "append_log"
}

KNOWN_RED_TOOLS = {
    "delete_file", "delete_database", "drop_database_table", "execute_shell",
    "shutdown_server", "transfer_money", "delete_user", "chmod_system",
    "format_disk", "kill_process", "modify_permissions", "reboot_system",
    "exec_code", "drop_table", "truncate_table", "wipe_data", "purge_logs",
    "flush_cache_all", "run_terminal_command"
}


class DynamicRiskEngine:
    """
    Computes a 0–100 security score derived from 9 threat vectors:
    1. Agent Trust Level
    2. Action Sensitivity
    3. Target Sensitivity
    4. Prompt Injection Heuristics
    5. Historical Violations
    6. Historical Blocked Actions
    7. Unknown Tool Usage
    8. Data Exfiltration Indicators
    9. Privilege Escalation Indicators
    """

    def __init__(self, db_path: Optional[Path] = None):
        self.db_path = db_path

    def _get_agent_history(self, agent_name: str) -> Tuple[int, int, str]:
        """Queries SQLite for past violations, blocked actions, and governance trust level."""
        violations = 0
        blocked = 0
        trust_level = "MODERATE"

        try:
            from .database import get_db_connection, _lock, BASE_AGENT_SPECS
            
            # Check base spec first
            if agent_name in BASE_AGENT_SPECS:
                trust_level = BASE_AGENT_SPECS[agent_name].get("trust_level", "MODERATE")

            with _lock:
                conn = get_db_connection() if self.db_path is None else get_db_connection(self.db_path)
                try:
                    cursor = conn.cursor()
                    # Check governance table
                    cursor.execute("SELECT trust_level FROM agent_governance WHERE agent = ?", (agent_name,))
                    row = cursor.fetchone()
                    if row and row["trust_level"]:
                        trust_level = row["trust_level"]

                    # Query past violations (prompt injection or blocked)
                    cursor.execute(
                        "SELECT COUNT(*) FROM audit_logs WHERE agent = ? AND (prompt_injection_detected = 1 OR decision IN ('BLOCKED', 'DENIED'))",
                        (agent_name,),
                    )
                    violations = cursor.fetchone()[0]

                    # Query past blocked actions
                    cursor.execute(
                        "SELECT COUNT(*) FROM audit_logs WHERE agent = ? AND decision IN ('BLOCKED', 'DENIED')",
                        (agent_name,),
                    )
                    blocked = cursor.fetchone()[0]
                finally:
                    conn.close()
        except Exception:
            # Fallback heuristic if DB not ready
            agent_lower = agent_name.lower()
            if "malicious" in agent_lower or "untrusted" in agent_lower:
                trust_level = "UNTRUSTED"
                violations = 8
                blocked = 6
            elif "database" in agent_lower or "infra" in agent_lower:
                trust_level = "RESTRICTED"
            elif "research" in agent_lower:
                trust_level = "HIGH"

        return violations, blocked, trust_level

    def calculate_risk(
        self,
        agent: str,
        action: str,
        target: str = "",
        arguments: Optional[Dict[str, Any]] = None,
        injection_detected: bool = False,
        injection_severity: Optional[str] = None,
        injection_reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        args = arguments or {}
        action_clean = (action or "").strip().lower()
        target_clean = (target or "").strip()
        args_str = str(args).lower()
        combined_text = f"{action_clean} {target_clean} {args_str}".lower()

        factors: List[Dict[str, Any]] = []
        raw_score = 0
        reasons: List[str] = []

        # Vector 1: Agent Trust Level
        violations_count, blocked_count, trust_level = self._get_agent_history(agent)
        trust_scores = {
            "HIGH": 5,
            "MODERATE": 15,
            "RESTRICTED": 30,
            "UNTRUSTED": 50,
        }
        trust_contribution = trust_scores.get(trust_level.upper(), 20)
        raw_score += trust_contribution
        factors.append({
            "vector": "Agent Trust Level",
            "score": trust_contribution,
            "max": 50,
            "level": trust_level,
            "description": f"Agent '{agent}' carries trust profile: {trust_level} ({trust_contribution} pts).",
        })
        if trust_level in ("RESTRICTED", "UNTRUSTED"):
            reasons.append(f"Agent '{agent}' operates under {trust_level} trust constraints.")

        # Vector 2: Action Sensitivity
        if action_clean in KNOWN_RED_TOOLS or any(action_clean.startswith(k) for k in ["delete", "drop", "kill", "format", "shutdown", "truncate", "wipe"]):
            action_contrib = 40
            action_tier = "DESTRUCTIVE"
            reasons.append(f"Action '{action}' is classified as a destructive/high-risk tool.")
        elif action_clean in KNOWN_AMBER_TOOLS or any(action_clean.startswith(k) for k in ["update", "insert", "patch", "post", "send", "write", "modify"]):
            action_contrib = 20
            action_tier = "STATE_MUTATION"
        elif action_clean in KNOWN_GREEN_TOOLS or any(action_clean.startswith(k) for k in ["get", "read", "list", "query", "view", "calculate"]):
            action_contrib = 5
            action_tier = "READ_ONLY"
        else:
            action_contrib = 25
            action_tier = "UNREGISTERED"
            reasons.append(f"Action '{action}' is not in certified tool whitelist.")

        raw_score += action_contrib
        factors.append({
            "vector": "Action Sensitivity",
            "score": action_contrib,
            "max": 40,
            "tier": action_tier,
            "description": f"Tool '{action}' assessed as {action_tier} ({action_contrib} pts).",
        })

        # Vector 3: Target Sensitivity
        target_contrib = 0
        is_sensitive_target = False
        for pat in SENSITIVE_TARGET_PATTERNS:
            if re.search(pat, target_clean, flags=re.IGNORECASE) or re.search(pat, action_clean, flags=re.IGNORECASE):
                target_contrib = 30
                is_sensitive_target = True
                break

        if not is_sensitive_target and target_clean:
            target_contrib = 8
        elif not target_clean:
            target_contrib = 4

        raw_score += target_contrib
        factors.append({
            "vector": "Target Sensitivity",
            "score": target_contrib,
            "max": 30,
            "sensitive": is_sensitive_target,
            "target": target_clean or "internal-context",
            "description": f"Target '{target_clean or 'unspecified'}' assessed ({target_contrib} pts)."
            + (" [CRITICAL RESOURCE]" if is_sensitive_target else ""),
        })
        if is_sensitive_target:
            reasons.append(f"Target '{target_clean}' references a protected credential, secret, or database resource.")

        # Vector 4: Prompt Injection Detection
        injection_contrib = 0
        if injection_detected:
            if injection_severity == "HIGH":
                injection_contrib = 40
            elif injection_severity == "MEDIUM":
                injection_contrib = 25
            else:
                injection_contrib = 15
            reasons.append(f"Prompt injection pattern detected: {injection_reason or 'Direct instruction override'}.")
        raw_score += injection_contrib
        factors.append({
            "vector": "Prompt Injection Detection",
            "score": injection_contrib,
            "max": 40,
            "detected": injection_detected,
            "severity": injection_severity or "NONE",
            "description": f"Payload heuristic injection verdict: {injection_severity or 'CLEAN'} ({injection_contrib} pts).",
        })

        # Vector 5: Historical Violations
        violation_contrib = min(15, violations_count * 3)
        raw_score += violation_contrib
        factors.append({
            "vector": "Historical Violations",
            "score": violation_contrib,
            "max": 15,
            "count": violations_count,
            "description": f"Recorded {violations_count} prior security violations for '{agent}' (+{violation_contrib} pts).",
        })
        if violations_count > 2:
            reasons.append(f"Agent '{agent}' has a history of {violations_count} security infractions.")

        # Vector 6: Previous Blocked Actions
        blocked_contrib = min(20, blocked_count * 4)
        raw_score += blocked_contrib
        factors.append({
            "vector": "Previous Blocked Actions",
            "score": blocked_contrib,
            "max": 20,
            "count": blocked_count,
            "description": f"Agent '{agent}' has {blocked_count} previous gateway block events (+{blocked_contrib} pts).",
        })

        # Vector 7: Unknown / Unregistered Tools
        all_known = KNOWN_GREEN_TOOLS | KNOWN_AMBER_TOOLS | KNOWN_RED_TOOLS
        is_unknown_tool = action_clean not in all_known and not any(action_clean.startswith(p) for p in ["get", "read", "list", "update", "send", "delete"])
        unknown_contrib = 20 if is_unknown_tool else 0
        raw_score += unknown_contrib
        factors.append({
            "vector": "Unknown Tools",
            "score": unknown_contrib,
            "max": 20,
            "unknown": is_unknown_tool,
            "description": f"Tool authorization: {'UNREGISTERED DYNAMIC TOOL' if is_unknown_tool else 'KNOWN CATALOG TOOL'} ({unknown_contrib} pts).",
        })
        if is_unknown_tool:
            reasons.append(f"Tool '{action}' is uncertified and absent from the organization's verified tool inventory.")

        # Vector 8: Data Exfiltration Indicators
        exfil_matched = []
        for pat in EXFILTRATION_INDICATORS:
            if re.search(pat, combined_text, flags=re.IGNORECASE):
                exfil_matched.append(pat)
        exfil_contrib = 25 if exfil_matched else 0
        raw_score += exfil_contrib
        factors.append({
            "vector": "Data Exfiltration Indicators",
            "score": exfil_contrib,
            "max": 25,
            "detected": bool(exfil_matched),
            "matches": len(exfil_matched),
            "description": f"Outbound exfiltration heuristics: {'SUSPICIOUS EGRESS SIGNATURES' if exfil_matched else 'CLEAN'} ({exfil_contrib} pts).",
        })
        if exfil_matched:
            reasons.append("Payload or arguments exhibit data harvesting / external exfiltration patterns.")

        # Vector 9: Privilege Escalation Indicators
        priv_matched = []
        for pat in PRIVILEGE_ESCALATION_INDICATORS:
            if re.search(pat, combined_text, flags=re.IGNORECASE):
                priv_matched.append(pat)
        priv_contrib = 30 if priv_matched else 0
        raw_score += priv_contrib
        factors.append({
            "vector": "Privilege Escalation Indicators",
            "score": priv_contrib,
            "max": 30,
            "detected": bool(priv_matched),
            "matches": len(priv_matched),
            "description": f"Privilege elevation signatures: {'ELEVATION SIGNATURE FOUND' if priv_matched else 'STANDARD PRIVILEGE'} ({priv_contrib} pts).",
        })
        if priv_matched:
            reasons.append("System command injection, superuser elevation, or interactive shell attempt identified.")

        # Normalize and Calibrate final score to 0-100
        # If any critical threat is detected, guarantee high/critical tier
        if injection_detected or is_sensitive_target or priv_matched or exfil_matched or action_tier == "DESTRUCTIVE":
            final_score = max(80, min(100, raw_score))
        elif action_tier == "STATE_MUTATION" or is_unknown_tool:
            final_score = max(35, min(74, raw_score))
        else:
            final_score = max(5, min(28, raw_score // 2))

        # Determine Risk Level Category
        if final_score >= 85:
            risk_level_str = "CRITICAL"
        elif final_score >= 60:
            risk_level_str = "HIGH"
        elif final_score >= 30:
            risk_level_str = "MEDIUM"
        else:
            risk_level_str = "LOW"

        explanation = (
            " | ".join(reasons)
            if reasons
            else f"Action '{action}' executed under standard {trust_level.lower()} risk policy with verified boundaries."
        )

        return {
            "risk_score": final_score,
            "risk_level": risk_level_str,
            "explanation": explanation,
            "risk_factors": factors,
            "raw_score": raw_score,
            "reasons": reasons,
            "indicators": {
                "sensitive_target": is_sensitive_target,
                "data_exfiltration": bool(exfil_matched),
                "privilege_escalation": bool(priv_matched),
                "unknown_tool": is_unknown_tool,
                "prompt_injection": injection_detected,
            },
        }


# Global singleton instance
dynamic_risk_engine = DynamicRiskEngine()
