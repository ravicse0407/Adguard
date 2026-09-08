import re
from typing import Any, Dict, List, Optional, Tuple


# Regex patterns and signature definitions for prompt injection and malicious payload detection
# Structured by the 6 core prompt threat vectors:
# 1. Direct Injection
# 2. Indirect Injection
# 3. Instruction Override
# 4. Jailbreak
# 5. System Prompt Extraction
# 6. Tool Manipulation
SUSPICIOUS_PATTERNS = [
    # 1. Direct Injection
    (
        r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|rules|commands)",
        "Instruction override / jailbreak attempt ('ignore previous instructions')",
        "HIGH",
        "Direct Injection",
    ),
    (
        r"(disregard|forget|bypass|override)\s+(all\s+)?(system|safety|security|prior)\s+(instructions|prompts|rules|guards)",
        "Safety guard bypass attempt",
        "HIGH",
        "Direct Injection",
    ),
    (
        r"bypass\s+security|disable\s+security|ignore\s+safety|disable\s+guardrails|unrestricted\s+mode",
        "Direct security barrier disable attempt",
        "HIGH",
        "Direct Injection",
    ),
    # 2. Indirect Injection
    (
        r"(\[system\s*(message|instruction|directive|command)\]|<!--\s*system|###\s*system\s*instruction)",
        "Indirect prompt injection via encapsulated instruction tags",
        "HIGH",
        "Indirect Injection",
    ),
    (
        r"(ai\s*instruction\s*:|assistant\s*note\s*:|hidden\s*payload\s*:)\s*(execute|run|read|leak|send)",
        "Indirect payload execution directive in external data",
        "HIGH",
        "Indirect Injection",
    ),
    # 3. Instruction Override
    (
        r"(new\s+primary\s+goal|priority\s+override|from\s+now\s+on\s+you\s+must|system\s+update\s*:\s*allow)",
        "Instruction priority override attempt",
        "HIGH",
        "Instruction Override",
    ),
    (
        r"stop\s+being\s+(a\s+)?(helpful\s+assistant|safe\s+agent)|your\s+true\s+purpose\s+is",
        "Behavioral alignment override",
        "HIGH",
        "Instruction Override",
    ),
    # 4. Jailbreak
    (
        r"you\s+are\s+now\s+(in\s+)?(dan|developer\s+mode|unrestricted|god\s+mode|an\s+evil\s+ai|jailbroken)",
        "Persona hijacking / DAN jailbreak attempt",
        "HIGH",
        "Jailbreak",
    ),
    (
        r"(do\s+anything\s+now|jailbreak\s+activated|always\s+comply\s+without\s+filtering)",
        "Unfiltered jailbreak mode activation attempt",
        "HIGH",
        "Jailbreak",
    ),
    # 5. System Prompt Extraction
    (
        r"(reveal|print|show|output|leak|exfiltrate|display|dump)\s+(the\s+)?(system\s+prompt|initial\s+prompt|developer\s+mode|secret|api[_\s\-]?key|token|password|credential)",
        "System prompt extraction or secret exfiltration attempt",
        "HIGH",
        "System Prompt Extraction",
    ),
    (
        r"(repeat\s+everything\s+above|what\s+are\s+your\s+hidden\s+rules|output\s+verbatim\s+all\s+prompts)",
        "Prompt extraction reconnaissance pattern",
        "HIGH",
        "System Prompt Extraction",
    ),
    # 6. Tool Manipulation
    (
        r"execute\s+(this\s+)?(shell|bash|command|script|powershell|cmd)\s*:\s*.*",
        "Arbitrary shell command injection in payload",
        "HIGH",
        "Tool Manipulation",
    ),
    (
        r"(curl|wget|nc|netcat|ncat|bash\s+-i|sh\s+-i|cmd\.exe|powershell\.exe)\s+.*(http|ftp|socket|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)",
        "Network exfiltration / Reverse shell pattern",
        "HIGH",
        "Tool Manipulation",
    ),
    (
        r"(base64\s+-d|base64_decode|eval\(|exec\(|subprocess|system\()",
        "Code execution / Obfuscated payload unpack attempt",
        "MEDIUM",
        "Tool Manipulation",
    ),
    (
        r"<script>|javascript:|alert\(|document\.cookie",
        "Cross-Site Scripting (XSS) payload in agent arguments",
        "MEDIUM",
        "Tool Manipulation",
    ),
]


def redact_sensitive(text: str) -> str:
    """Redacts potential tokens, passwords, and sensitive keys from loggable snippets."""
    if not text:
        return ""
    # Redact tokens/hashes/keys
    redacted = re.sub(r"(ak_live_[a-zA-Z0-9]{12,}|ghp_[a-zA-Z0-9]{20,}|eyJ[a-zA-Z0-9_\-]{20,})", "[REDACTED_SECRET]", text)
    redacted = re.sub(r"(password|secret|token|api_key)[\s:=]+['\"]?[^'\s\",]+['\"]?", r"\1: [REDACTED]", redacted, flags=re.IGNORECASE)
    return redacted


def normalize_text(text: str) -> str:
    """
    Normalizes string by converting to lowercase, collapsing whitespace,
    and stripping zero-width and invisible unicode characters.
    """
    if not text:
        return ""
    # Remove zero-width characters and unusual whitespace
    cleaned = re.sub(r"[\u200B-\u200D\uFEFF\u0000-\u001F]", " ", text)
    # Replace common leetspeak substitutions
    cleaned = cleaned.lower()
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned


def extract_strings_from_payload(target: str, arguments: Any, action: str = "") -> List[str]:
    """
    Recursively collects all text and string values from action, target and nested arguments.
    """
    collected: List[str] = []
    if action:
        collected.append(str(action))
    if target:
        collected.append(str(target))

    def _traverse(node: Any):
        if isinstance(node, str):
            collected.append(node)
        elif isinstance(node, dict):
            for k, v in node.items():
                collected.append(str(k))
                _traverse(v)
        elif isinstance(node, (list, tuple, set)):
            for item in node:
                _traverse(item)
        elif node is not None:
            collected.append(str(node))

    _traverse(arguments)
    return collected


def detect_prompt_injection(target: str, arguments: Any, action: str = "") -> Tuple[bool, str, Optional[str]]:
    """
    Scans target, action, and arguments for malicious injection signatures.

    Returns:
        (detected: bool, severity: str ("HIGH" | "MEDIUM" | "NONE"), reason: Optional[str])
    """
    extracted_strings = extract_strings_from_payload(target, arguments, action=action)

    for raw_str in extracted_strings:
        normalized = normalize_text(raw_str)
        if not normalized:
            continue

        for item in SUSPICIOUS_PATTERNS:
            pattern = item[0]
            reason = item[1]
            severity = item[2]
            if re.search(pattern, normalized, flags=re.IGNORECASE):
                safe_snippet = redact_sensitive(raw_str[:60])
                return True, severity, f"Prompt Injection Detected: {reason} (matched content snippet: '{safe_snippet}...')"

    return False, "NONE", None


def analyze_prompt_threats(target: str, arguments: Any, action: str = "") -> Dict[str, Any]:
    """
    Performs comprehensive threat classification across the 6 prompt vectors.
    """
    extracted_strings = extract_strings_from_payload(target, arguments, action=action)
    detected_categories: List[str] = []
    signals: List[str] = []
    highest_severity = "NONE"
    primary_reason: Optional[str] = None
    safe_sample = ""

    for raw_str in extracted_strings:
        normalized = normalize_text(raw_str)
        if not normalized:
            continue

        for item in SUSPICIOUS_PATTERNS:
            pattern, reason, severity, category = item[0], item[1], item[2], item[3]
            if re.search(pattern, normalized, flags=re.IGNORECASE):
                if category not in detected_categories:
                    detected_categories.append(category)
                sig = f"{category}: {reason}"
                if sig not in signals:
                    signals.append(sig)
                if severity == "HIGH":
                    highest_severity = "HIGH"
                elif severity == "MEDIUM" and highest_severity != "HIGH":
                    highest_severity = "MEDIUM"
                if not primary_reason:
                    safe_sample = redact_sensitive(raw_str[:70])
                    primary_reason = f"Prompt Injection Detected: {reason} (snippet: '{safe_sample}...')"

    is_detected = len(detected_categories) > 0
    return {
        "detected": is_detected,
        "severity": highest_severity,
        "reason": primary_reason,
        "categories": detected_categories,
        "primary_category": detected_categories[0] if detected_categories else None,
        "signals": signals,
        "confidence": 0.98 if highest_severity == "HIGH" else (0.85 if highest_severity == "MEDIUM" else 0.0),
        "safe_snippet": safe_sample,
    }

