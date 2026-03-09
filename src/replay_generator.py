"""
replay_generator.py — Generador de scripts de replay para detecciones de terceros.

Para técnicas que involucran plataformas 3P (email, cloud, SaaS),
genera scripts .sh que replayan la detección vía API/CLI en lugar de
ejecutarla orgánicamente en el lab.

La ejecución orgánica de estas técnicas (email phishing, cloud API calls, etc.)
no es factible en el lab aislado — el replay permite mostrar la detección
de CrowdStrike sin necesitar infraestructura externa real.

Uso:
    gen = ReplayGenerator()
    scripts = gen.generate_all(attack_sequence, iocs)
    # scripts: [{"stage": "...", "filename": "...", "type": "replay", "content": "..."}]
"""

from typing import List, Dict, Any


# ── Técnicas que requieren replay 3P (no ejecutables en lab aislado) ─────────
_REPLAY_TECHNIQUE_PREFIXES = {
    "T1566",   # Phishing (all subtechniques)
    "T1598",   # Phishing for Information
    "T1078.004", # Valid Accounts - Cloud
    "T1537",   # Transfer Data to Cloud Account
    "T1530",   # Data from Cloud Storage Object
    "T1619",   # Cloud Storage Object Discovery
    "T1526",   # Cloud Service Discovery
    "T1199",   # Trusted Relationship
    "T1195",   # Supply Chain Compromise
    "T1114",   # Email Collection
    "T1048.002", # Exfil over asymmetric encrypted non-C2 protocol (cloud)
    "T1567",   # Exfiltration Over Web Service
}

# ── Palabras clave en descripción que indican replay ─────────────────────────
_REPLAY_KEYWORDS = [
    "email", "phish", "mimecast", "office365", "o365", "exchange",
    "cloud", "aws", "azure", "gcp", "s3", "blob", "cloudtrail",
    "saas", "okta", "salesforce", "slack", "teams", "sharepoint",
    "smtp", "imap", "pop3",
]


def classify_stage(stage: Dict[str, Any]) -> str:
    """
    Clasifica un stage como 'native' (ejecutable en lab) o 'replay' (3P).

    Returns: 'native' | 'replay'
    """
    tid         = stage.get("technique_id", "")
    exec_method = stage.get("execution_method", "").lower()
    description = (
        stage.get("description", "") + " " +
        stage.get("technical_details", "") + " " +
        stage.get("execution_approach", "")
    ).lower()

    # Exact or prefix match on technique ID
    if tid in _REPLAY_TECHNIQUE_PREFIXES:
        return "replay"
    base_tid = tid.split(".")[0]  # T1566 from T1566.001
    if base_tid in _REPLAY_TECHNIQUE_PREFIXES:
        return "replay"

    # Execution method or keyword match
    if exec_method in ("email", "cloud_api", "saas", "smtp"):
        return "replay"
    if any(kw in description for kw in _REPLAY_KEYWORDS):
        return "replay"

    return "native"


# ── Script builders ───────────────────────────────────────────────────────────

def _header(stage: Dict[str, Any]) -> str:
    return f"""#!/usr/bin/env bash
# ================================================================
# THREATHUNT AI — REPLAY SCRIPT
# Stage:       {stage.get('stage', 'unknown')}
# Technique:   {stage.get('technique_id', '')}
# Description: {stage.get('description', '')}
#
# This stage involves a third-party platform (email/cloud/SaaS).
# Organic execution is not available in the isolated lab.
# This script replays the detection via API/CLI.
#
# PREREQUISITES:
#   Fill the environment variables below before running.
#   Run from: C2 host (10.5.9.41) or Kali (10.5.9.21)
# ================================================================
set -euo pipefail

# ── Lab targets ──────────────────────────────────────────────────
C2_HOST="10.5.9.41"
WIN_VICTIM="10.5.9.31"
LINUX_VICTIM="10.5.9.40"

"""


def _mimecast_replay(stage: Dict[str, Any], iocs: Dict[str, List[str]]) -> str:
    domains = iocs.get("domains", ["malicious-actor.com"])
    sender_domain = domains[0] if domains else "evil-attacker.com"
    hashes  = iocs.get("sha256", iocs.get("md5", []))
    subject = "Urgent: Invoice Q4-Overdue" if not hashes else f"Document_{hashes[0][:8]}.pdf"
    return f"""
# ── Environment variables ─────────────────────────────────────
# export MIMECAST_AUTH_KEY="your_base64_auth_key"
# export MIMECAST_APP_ID="your_app_id"
# export VICTIM_EMAIL="victim@targetcorp.com"

AUTH_KEY="${{MIMECAST_AUTH_KEY:-PLACEHOLDER}}"
APP_ID="${{MIMECAST_APP_ID:-PLACEHOLDER}}"
VICTIM="${{VICTIM_EMAIL:-victim@lab.local}}"

echo "[REPLAY] Injecting email phishing event via Mimecast API..."
echo "[REPLAY] Technique: {stage.get('technique_id', 'T1566')} — {stage.get('description', 'Phishing')}"
echo "[REPLAY] Simulated sender: attacker@{sender_domain}"

# ── Step 1: Inject TTP URL event ─────────────────────────────
# Triggers Mimecast TTP log → ingested by CrowdStrike via integration
curl -sf -X POST "https://eu-api.mimecast.com/api/ttp/url/decode-url" \\
  -H "Authorization: Bearer $AUTH_KEY" \\
  -H "x-mc-app-id: $APP_ID" \\
  -H "Content-Type: application/json" \\
  -d '{{
    "data": [{{
      "url": "http://{sender_domain}/payload.exe",
      "from": "attacker@{sender_domain}",
      "to": "'"$VICTIM"'",
      "subject": "{subject}"
    }}]
  }}' && echo "[OK] Mimecast TTP event injected" \\
  || echo "[WARN] Mimecast API call failed — check MIMECAST_AUTH_KEY"

echo "[REPLAY] Expected CrowdStrike detection: Email — Malicious URL Clicked (via Mimecast integration)"
echo "[REPLAY] Check: Falcon XDR → Activity → Email events timeline"
echo ""
echo "[CLEANUP] No host artifacts to clean — platform-level event only."
"""


def _o365_replay(stage: Dict[str, Any], iocs: Dict[str, List[str]]) -> str:
    return f"""
# ── Environment variables ─────────────────────────────────────
# export O365_TENANT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
# export O365_CLIENT_ID="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
# export O365_CLIENT_SECRET="your_client_secret"

TENANT="${{O365_TENANT_ID:-PLACEHOLDER}}"
CLIENT_ID="${{O365_CLIENT_ID:-PLACEHOLDER}}"
CLIENT_SECRET="${{O365_CLIENT_SECRET:-PLACEHOLDER}}"

echo "[REPLAY] Simulating Microsoft 365 / Azure AD activity..."
echo "[REPLAY] Technique: {stage.get('technique_id', '')} — {stage.get('description', '')}"

# ── Step 1: Obtain OAuth token ────────────────────────────────
# Suspicious app-level authentication → Falcon Identity Protection alert
echo "[REPLAY] Requesting OAuth token (triggers Azure AD sign-in log)..."
TOKEN=$(curl -sf -X POST \\
  "https://login.microsoftonline.com/$TENANT/oauth2/v2.0/token" \\
  -d "client_id=$CLIENT_ID&client_secret=$CLIENT_SECRET&grant_type=client_credentials&scope=https://graph.microsoft.com/.default" \\
  | python3 -c "import sys,json; print(json.load(sys.stdin).get('access_token','FAILED'))" 2>/dev/null)

if [[ "$TOKEN" == "FAILED" || -z "$TOKEN" ]]; then
  echo "[WARN] Failed to obtain OAuth token — set O365_TENANT_ID, O365_CLIENT_ID, O365_CLIENT_SECRET"
  exit 1
fi

# ── Step 2: Enumerate users (lateral discovery via Graph API) ──
# CrowdStrike Identity Protection: Anomalous Graph API user enumeration
echo "[REPLAY] Enumerating users via Graph API (triggers suspicious cloud discovery alert)..."
curl -sf -H "Authorization: Bearer $TOKEN" \\
  "https://graph.microsoft.com/v1.0/users?\\$top=10&\\$select=displayName,userPrincipalName" \\
  | python3 -c "import sys,json; [print('  -', u.get('userPrincipalName','?')) for u in json.load(sys.stdin).get('value',[])]" 2>/dev/null \\
  || echo "[WARN] Graph API enumeration failed"

echo "[REPLAY] Expected CrowdStrike detection: Suspicious Azure AD Enumeration — Identity Protection"
echo "[REPLAY] Check: Falcon Identity Protection → Incidents"
echo ""
echo "[CLEANUP] No persistent changes made — read-only API calls only."
"""


def _aws_replay(stage: Dict[str, Any], iocs: Dict[str, List[str]]) -> str:
    return f"""
# ── Environment variables ─────────────────────────────────────
# export AWS_ACCESS_KEY_ID="AKIA..."
# export AWS_SECRET_ACCESS_KEY="..."
# export AWS_DEFAULT_REGION="us-east-1"

echo "[REPLAY] Simulating AWS cloud activity..."
echo "[REPLAY] Technique: {stage.get('technique_id', '')} — {stage.get('description', '')}"

# ── Step 0: Verify credentials ────────────────────────────────
aws sts get-caller-identity 2>/dev/null || {{
  echo "[ERROR] AWS credentials not configured."
  echo "[ERROR] Set AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_DEFAULT_REGION"
  exit 1
}}

# ── Step 1: Enumerate S3 buckets (suspicious cloud discovery) ──
# CloudTrail → ListBuckets → CrowdStrike Cloud Security alert
echo "[REPLAY] Enumerating S3 buckets (read-only, triggers CloudTrail ListBuckets event)..."
aws s3 ls 2>/dev/null | head -10 || echo "[WARN] No S3 access"

# ── Step 2: Enumerate IAM users ───────────────────────────────
# CloudTrail → ListUsers → Suspicious IAM enumeration
echo "[REPLAY] Enumerating IAM users (triggers CloudTrail IAM event)..."
aws iam list-users --query 'Users[].UserName' --output text 2>/dev/null | head -5 || echo "[WARN] No IAM access"

# ── Step 3: Describe EC2 instances ────────────────────────────
echo "[REPLAY] Enumerating EC2 instances (triggers CloudTrail DescribeInstances)..."
aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output text 2>/dev/null || true

echo "[REPLAY] Expected CrowdStrike detection: Suspicious AWS Discovery Activity — Cloud Security"
echo "[REPLAY] Check: Falcon Cloud Security → Detections → Cloud IOAs"
echo ""
echo "[CLEANUP] Read-only operations — no cleanup required."
"""


def _generic_replay(stage: Dict[str, Any]) -> str:
    return f"""
echo "[REPLAY] Stage: {stage.get('stage', 'unknown')}"
echo "[REPLAY] Technique: {stage.get('technique_id', '')} — {stage.get('description', '')}"
echo ""
echo "[INFO] This stage involves a third-party platform integration."
echo "[INFO] Manual action required:"
echo ""
echo "  Execution approach: {stage.get('execution_approach', 'See playbook for details')}"
echo ""
echo "[REPLAY] Expected CrowdStrike detection:"
for det in {repr(stage.get('crowdstrike_detections', ['See playbook']))}; do
  echo "  - $det"
done
echo ""
echo "[CLEANUP] Platform-level event — no host artifacts to clean."
"""


# ── Public API ────────────────────────────────────────────────────────────────

class ReplayGenerator:
    """
    Genera scripts .sh de replay para stages con detecciones en plataformas 3P.
    """

    def classify_stage(self, stage: Dict[str, Any]) -> str:
        return classify_stage(stage)

    def generate_script(
        self,
        stage: Dict[str, Any],
        iocs: Dict[str, List[str]],
    ) -> str:
        """Genera el contenido de un script .sh de replay para el stage dado."""
        header = _header(stage)
        description = (
            stage.get("description", "") + " " +
            stage.get("technical_details", "") + " " +
            stage.get("execution_approach", "")
        ).lower()

        if any(kw in description for kw in ("mimecast", "email", "phish", "smtp", "mail")):
            body = _mimecast_replay(stage, iocs)
        elif any(kw in description for kw in ("o365", "office365", "azure", "microsoft", "graph api", "teams")):
            body = _o365_replay(stage, iocs)
        elif any(kw in description for kw in ("aws", "s3", "cloudtrail", "iam", "ec2", "lambda")):
            body = _aws_replay(stage, iocs)
        else:
            body = _generic_replay(stage)

        return header + body

    def generate_all(
        self,
        attack_sequence: List[Dict],
        iocs: Dict[str, List[str]],
    ) -> List[Dict[str, Any]]:
        """
        Procesa la secuencia de ataque y genera scripts de replay para stages 3P.

        Returns list of dicts: {stage, filename, type, technique_id, content}
        """
        scripts = []
        for stage in attack_sequence:
            if classify_stage(stage) == "replay":
                content  = self.generate_script(stage, iocs)
                filename = f"replay_{stage.get('stage', f'stage_{len(scripts)+1}')}.sh"
                scripts.append({
                    "stage":        stage.get("stage", ""),
                    "filename":     filename,
                    "type":         "replay",
                    "technique_id": stage.get("technique_id", ""),
                    "description":  stage.get("description", ""),
                    "content":      content,
                })
        return scripts
