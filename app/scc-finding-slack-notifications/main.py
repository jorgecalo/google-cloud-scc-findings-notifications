"""Security Command Center (SCC) finding notifications to Slack.

Cloud Run function (2nd gen) triggered by Eventarc when SCC publishes a
finding notification to the Pub/Sub topic. The function formats the finding
with a Slack Block Kit template and posts it with chat.postMessage.

Runtime: Python 3.13. Entry point: send_slack_chat_notification

Environment variables:
  SLACK_BOT_TOKEN         Slack bot token. Injected from Secret Manager.
  SLACK_CHANNEL           Channel ID (recommended) or name to post to.
  GTI_API_KEY             Optional Google Threat Intelligence (VirusTotal v3)
                          API key to enrich IoCs (IPs, domains, SHA-256 hashes)
                          directly in the Slack alert.
  ALLOWED_PROJECTS        Optional comma separated list of project IDs or
                          display names. When set, other projects are skipped.
  ALLOWED_EXPLOITABILITY  Allowed CVE exploitationActivity values (default:
                          WIDE,AVAILABLE,CONFIRMED).
  ALLOWED_CVE_IMPACT      Allowed CVE impact values (default: CRITICAL,HIGH).
  DEDUP_WINDOW_SECONDS    Organization-wide cooldown window for repeated alerts
                          of the same CVE (default: 3600).
  MAX_EVENT_AGE_SECONDS   Events older than this are dropped instead of being
                          retried forever. Default 3600.

Error handling:
  Transient errors (network, HTTP 429/5xx, Slack internal errors) raise, so
  Eventarc redelivers the event. Permanent errors (bad payload, invalid token,
  unknown channel, invalid blocks) are logged with severity ERROR and the
  event is acknowledged, so it is not retried.
"""

import base64
import copy
import ipaddress
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import quote

try:
    import requests
except ImportError:
    # Fallback shim so local CLI dry-runs work even without pip packages installed
    class _UrllibResponse:
        def __init__(self, status_code, body_bytes):
            self.status_code = status_code
            self._body = body_bytes

        def json(self):
            return json.loads(self._body.decode("utf-8"))

    class _UrllibRequestsShim:
        class RequestException(Exception):
            pass

        class ConnectionError(RequestException):
            pass

        @staticmethod
        def get(url, headers=None, timeout=10):
            req = urllib.request.Request(url, headers=headers or {}, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return _UrllibResponse(resp.status, resp.read())
            except urllib.error.HTTPError as exc:
                return _UrllibResponse(exc.code, exc.read())
            except Exception as exc:
                raise _UrllibRequestsShim.RequestException(str(exc)) from exc

        @staticmethod
        def post(url, headers=None, data=None, timeout=10):
            payload = data.encode("utf-8") if isinstance(data, str) else data
            req = urllib.request.Request(url, data=payload, headers=headers or {}, method="POST")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    return _UrllibResponse(resp.status, resp.read())
            except urllib.error.HTTPError as exc:
                return _UrllibResponse(exc.code, exc.read())
            except Exception as exc:
                raise _UrllibRequestsShim.RequestException(str(exc)) from exc

    requests = _UrllibRequestsShim()

try:
    import functions_framework
except ImportError:  # Allows the local dry run without the framework.
    functions_framework = None

SLACK_API_URL = "https://slack.com/api/chat.postMessage"
GTI_API_BASE_URL = "https://www.virustotal.com/api/v3"
SLACK_SECTION_TEXT_LIMIT = 3000
SLACK_TIMEOUT_SECONDS = 10
GTI_TIMEOUT_SECONDS = 4
CONSOLE_FINDINGS_URL = "https://console.cloud.google.com/security/command-center/findings"
TEMPLATE_PATH = Path(__file__).parent / "block_templates" / "finding-detail.json"

PLACEHOLDER_KEYS = (
    "SUBJECT", "WEB_LINK", "PROJECT_ID", "RESOURCE", "SEVERITY", "SEV_EMO",
    "STATE", "TIMESTAMP", "CVE_DETAILS", "GTI_DETAILS", "EXPLANATION",
    "RECOMMENDATION", "INSTRUCT",
)

SEVERITY_EMOJI = {"CRITICAL": ":rotating_light:", "HIGH": ":warning:"}

# Slack API errors worth retrying. Everything else is treated as permanent.
TRANSIENT_SLACK_ERRORS = {
    "ratelimited",
    "internal_error",
    "fatal_error",
    "service_unavailable",
    "request_timeout",
}

_template_cache = None
_recent_cve_alerts_cache = {}
_gti_enrichment_cache = {}


class TransientError(Exception):
    """Raised to make Eventarc redeliver the event."""


class PermanentError(Exception):
    """The event can never succeed. It is logged and acknowledged."""


def log(severity, message, **fields):
    """Write a structured log line that Cloud Logging parses from stdout."""
    print(json.dumps({"severity": severity, "message": message, **fields}), flush=True)


# --------------------------------------------------------------------------
# Parsing & Filtering
# --------------------------------------------------------------------------

def parse_pubsub_message(event_data):
    """Return the SCC notification dict from an Eventarc Pub/Sub event body."""
    try:
        encoded = event_data["message"]["data"]
        return json.loads(base64.b64decode(encoded).decode("utf-8"))
    except (KeyError, TypeError, ValueError) as exc:
        raise PermanentError(f"Cannot decode Pub/Sub message: {exc}") from exc


def event_age_seconds(event_time, now=None):
    """Age of an RFC 3339 timestamp in seconds, or None when unparsable."""
    if not event_time:
        return None
    try:
        ts = datetime.fromisoformat(str(event_time).replace("Z", "+00:00"))
    except ValueError:
        return None
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    now = now or datetime.now(timezone.utc)
    return (now - ts).total_seconds()


def allowed_projects():
    raw = os.environ.get("ALLOWED_PROJECTS", "")
    return {p.strip() for p in raw.split(",") if p.strip()}


def allowed_exploitability():
    raw = os.environ.get("ALLOWED_EXPLOITABILITY", "WIDE,AVAILABLE,CONFIRMED")
    return {x.strip().upper() for x in raw.split(",") if x.strip()}


def allowed_cve_impact():
    raw = os.environ.get("ALLOWED_CVE_IMPACT", "CRITICAL,HIGH")
    return {x.strip().upper() for x in raw.split(",") if x.strip()}


def dedup_window_seconds():
    return int(os.environ.get("DEDUP_WINDOW_SECONDS", "3600"))


def project_identifiers(resource):
    """All values a user may use to name the finding's project."""
    ids = set()
    for key in ("projectDisplayName", "project"):
        value = resource.get(key)
        if value:
            ids.add(value)
            ids.add(value.rsplit("/", 1)[-1])
    return ids


def extract_cve_details(finding):
    """Extract normalized CVE metadata when a finding has a CVE record."""
    vulnerability = finding.get("vulnerability") or {}
    cve = vulnerability.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None

    cvssv3 = cve.get("cvssv3") or {}
    offending_pkg = vulnerability.get("offendingPackage") or {}
    fixed_pkg = vulnerability.get("fixedPackage") or {}

    return {
        "cve_id": str(cve_id),
        "exploitation_activity": str(cve.get("exploitationActivity", "NO_KNOWN")).upper(),
        "impact": str(cve.get("impact", "RISK_RATING_UNSPECIFIED")).upper(),
        "observed_in_the_wild": bool(cve.get("observedInTheWild", False)),
        "zero_day": bool(cve.get("zeroDay", False)),
        "upstream_fix_available": bool(cve.get("upstreamFixAvailable", False)),
        "cvss_score": cvssv3.get("baseScore"),
        "package_name": offending_pkg.get("packageName"),
        "fixed_version": fixed_pkg.get("version") or fixed_pkg.get("cpeUri"),
    }


def _is_routable_ip(ip_str):
    """Return True if ip_str is a valid non-RFC1918/non-loopback IP address."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return not (addr.is_loopback or addr.is_link_local or addr.is_multicast)
    except ValueError:
        return False


def extract_iocs(finding, max_iocs=3):
    """Extract up to max_iocs deduplicated IoCs [(ioc_type, value)] from an SCC finding."""
    iocs = []
    seen = set()

    def add_ioc(ioc_type, val):
        if not val or not isinstance(val, str):
            return
        val = val.strip()
        if not val or (ioc_type, val) in seen:
            return
        if ioc_type == "ip_addresses" and not _is_routable_ip(val):
            return
        seen.add((ioc_type, val))
        iocs.append((ioc_type, val))

    indicator = finding.get("indicator") or {}
    for ip in indicator.get("ipAddresses") or []:
        add_ioc("ip_addresses", ip)
    for dom in indicator.get("domains") or []:
        add_ioc("domains", dom)
    for sig in indicator.get("signatures") or []:
        if isinstance(sig, dict) and sig.get("sha256"):
            add_ioc("files", sig["sha256"])

    props = (finding.get("sourceProperties") or {}).get("properties") or {}
    if isinstance(props, dict):
        for key in ("ip", "ips", "ipAddress", "destinationIp"):
            val = props.get(key)
            for item in (val if isinstance(val, list) else [val]):
                add_ioc("ip_addresses", item)
        for key in ("domain", "domains", "host"):
            val = props.get(key)
            for item in (val if isinstance(val, list) else [val]):
                add_ioc("domains", item)
        for key in ("sha256", "fileHash"):
            val = props.get(key)
            for item in (val if isinstance(val, list) else [val]):
                add_ioc("files", item)

    for conn in finding.get("connections") or []:
        if isinstance(conn, dict):
            add_ioc("ip_addresses", conn.get("destinationIp"))

    for proc in finding.get("processes") or []:
        if isinstance(proc, dict):
            binary = proc.get("binary") or {}
            add_ioc("files", binary.get("sha256"))

    return iocs[:max_iocs]


def query_gti_ioc(ioc_type, ioc_value, api_key, session=requests):
    """Query Google Threat Intelligence (VirusTotal v3) for a single IoC with caching."""
    cache_key = (ioc_type, ioc_value)
    now = time.time()
    cached = _gti_enrichment_cache.get(cache_key)
    if cached and (now - cached[0]) < 3600:
        return cached[1]

    url = f"{GTI_API_BASE_URL}/{ioc_type}/{quote(ioc_value, safe='')}"
    try:
        resp = session.get(
            url,
            headers={"x-apikey": api_key.strip(), "Accept": "application/json"},
            timeout=GTI_TIMEOUT_SECONDS,
        )
        if resp.status_code != 200:
            return None
        attrs = (resp.json().get("data") or {}).get("attributes") or {}
    except Exception as exc:
        log("WARNING", f"GTI lookup failed for {ioc_value}: {exc}")
        return None

    stats = attrs.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    total = sum(int(v or 0) for v in stats.values()) or 0

    gti_assessment = attrs.get("gti_assessment") or {}
    verdict_obj = gti_assessment.get("verdict") or {}
    score_obj = gti_assessment.get("threat_score") or {}
    gti_verdict = verdict_obj.get("value") if isinstance(verdict_obj, dict) else None
    threat_score = score_obj.get("value") if isinstance(score_obj, dict) else attrs.get("reputation")

    if not gti_verdict:
        if malicious >= 3:
            gti_verdict = "MALICIOUS"
        elif malicious >= 1 or suspicious >= 1:
            gti_verdict = "SUSPICIOUS"
        else:
            gti_verdict = "BENIGN / CLEAN"

    gui_type = {"ip_addresses": "ip-address", "domains": "domain", "files": "file"}.get(ioc_type, "search")
    result = {
        "ioc": ioc_value,
        "type": ioc_type,
        "verdict": gti_verdict.replace("VERDICT_", ""),
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "threat_score": threat_score,
        "as_owner": attrs.get("as_owner"),
        "country": attrs.get("country"),
        "gui_url": f"https://www.virustotal.com/gui/{gui_type}/{quote(ioc_value, safe='')}",
    }
    _gti_enrichment_cache[cache_key] = (now, result)
    return result


def format_gti_enrichment(finding, api_key=None, session=requests):
    """Build the Slack mrkdwn summary for all IoCs in the finding when GTI_API_KEY is set."""
    api_key = (api_key or os.environ.get("GTI_API_KEY") or "").strip()
    if not api_key:
        return None
    iocs = extract_iocs(finding)
    if not iocs:
        return None

    lines = ["*🔎 Google Threat Intelligence (GTI) Verdict:*"]
    for ioc_type, ioc_val in iocs:
        info = query_gti_ioc(ioc_type, ioc_val, api_key, session=session)
        if not info:
            continue
        verdict = info["verdict"]
        if "MALICIOUS" in verdict:
            badge = ":red_circle: *MALICIOUS*"
        elif "SUSPICIOUS" in verdict:
            badge = ":large_orange_circle: *SUSPICIOUS*"
        else:
            badge = ":large_green_circle: *CLEAN / BENIGN*"

        meta_parts = [f"Detections: `{info['malicious']}/{info['total']}`"]
        if info.get("threat_score") is not None:
            meta_parts.append(f"Score: `{info['threat_score']}`")
        if info.get("as_owner"):
            owner = escape_mrkdwn(str(info["as_owner"]))
            country = f", {escape_mrkdwn(str(info['country']))}" if info.get("country") else ""
            meta_parts.append(f"ASN: `{owner}{country}`")

        safe_ioc = escape_mrkdwn(info["ioc"])
        lines.append(
            f"• *IoC*: <{info['gui_url']}|`{safe_ioc}`> — {badge} ({' | '.join(meta_parts)})"
        )

    return "\n".join(lines) if len(lines) > 1 else None


def should_notify(notification):
    """Validate project allowlist and CVE exploitability/impact + org deduplication."""
    allow = allowed_projects()
    if allow and not (project_identifiers(notification.get("resource") or {}) & allow):
        return False

    finding = notification.get("finding") or {}
    cve_info = extract_cve_details(finding)
    if cve_info is not None:
        exploit = cve_info["exploitation_activity"]
        impact = cve_info["impact"]
        is_exploitable = (
            exploit in allowed_exploitability()
            or cve_info["observed_in_the_wild"]
            or cve_info["zero_day"]
        )
        if not is_exploitable or impact not in allowed_cve_impact():
            return False

        # Organization-wide deduplication per CVE within DEDUP_WINDOW_SECONDS
        window = dedup_window_seconds()
        if window > 0:
            parts = (finding.get("name") or "organizations/org").split("/")
            org_id = parts[1] if len(parts) > 1 else "org"
            dedup_key = f"org::{org_id}::{cve_info['cve_id']}"
            now = time.time()
            last_sent = _recent_cve_alerts_cache.get(dedup_key)
            if last_sent is not None and (now - last_sent) < window:
                return False
            _recent_cve_alerts_cache[dedup_key] = now

    return True


# --------------------------------------------------------------------------
# Formatting
# --------------------------------------------------------------------------

def escape_mrkdwn(text):
    """Escape the three characters Slack treats as control characters."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def as_text(value):
    """Turn a sourceProperties value into display text. Empty becomes None."""
    if value is None or value == "" or value == {} or value == []:
        return None
    if isinstance(value, str):
        return value.strip() or None
    return json.dumps(value, ensure_ascii=False)


def truncate(text, limit):
    return text if len(text) <= limit else text[: limit - 1] + "…"


def console_url(finding_name):
    """Deep link to the finding in the Google Cloud console.

    Works for organization, folder and project level SCC activations and for
    both v1 and v2 finding names.
    """
    parts = (finding_name or "").split("/")
    if len(parts) < 2:
        return CONSOLE_FINDINGS_URL
    scope, scope_id = parts[0], parts[1]
    resource_id = quote(finding_name, safe="/")
    if scope == "organizations":
        return (f"{CONSOLE_FINDINGS_URL}?organizationId={scope_id}&orgonly=true"
                f"&supportedpurview=organizationId&resourceId={resource_id}")
    if scope == "folders":
        return (f"{CONSOLE_FINDINGS_URL}?folder={scope_id}"
                f"&supportedpurview=folder&resourceId={resource_id}")
    if scope == "projects":
        return (f"{CONSOLE_FINDINGS_URL}?project={scope_id}"
                f"&supportedpurview=project&resourceId={resource_id}")
    return CONSOLE_FINDINGS_URL


def finding_values(notification):
    """Extract the display values for the template from a notification.

    Values are Slack escaped. A value of None removes the block that uses it.
    """
    finding = notification.get("finding") or {}
    resource = notification.get("resource") or {}
    props = finding.get("sourceProperties") or {}
    cve_info = extract_cve_details(finding)

    severity = finding.get("severity") or "SEVERITY_UNSPECIFIED"
    project = (resource.get("projectDisplayName")
               or (resource.get("project") or "").rsplit("/", 1)[-1]
               or "n/a")
    resource_label = (resource.get("displayName")
                      or resource.get("name")
                      or finding.get("resourceName")
                      or "n/a")

    # Security Health Analytics uses sourceProperties. Threat detection
    # services and newer detectors use description and nextSteps instead.
    explanation = as_text(props.get("Explanation")) or as_text(finding.get("description"))
    recommendation = as_text(props.get("Recommendation")) or as_text(finding.get("nextSteps"))
    instructions = as_text(props.get("ExceptionInstructions"))

    def esc(value):
        return None if value is None else escape_mrkdwn(value)

    cve_details_text = None
    subject_text = esc(finding.get("category") or "Unknown category")

    if cve_info is not None:
        cve_id = esc(cve_info["cve_id"])
        exploit = esc(cve_info["exploitation_activity"])
        impact = esc(cve_info["impact"])
        cvss_str = str(cve_info["cvss_score"]) if cve_info["cvss_score"] is not None else "n/a"
        fix_str = "Yes :white_check_mark:" if cve_info["upstream_fix_available"] else "No :x:"
        parts = (finding.get("name") or "").split("/")
        org_id = parts[1] if len(parts) > 1 and parts[0] == "organizations" else None
        org_link = (
            f" | <{CONSOLE_FINDINGS_URL}?organizationId={org_id}&orgonly=true&supportedpurview=organizationId|View Org-Wide in SCC>"
            if org_id else ""
        )
        subject_text = f"[{exploit} EXPLOIT | {impact} IMPACT] {cve_id} ({subject_text})"
        cve_details_text = (
            f"*CVE*: <https://nvd.nist.gov/vuln/detail/{cve_id}|{cve_id}>{org_link}\n"
            f"*Exploitability*: *{exploit}* | *Impact*: *{impact}*\n"
            f"*CVSSv3*: `{esc(cvss_str)}` | *Upstream Fix*: {fix_str}"
        )
        if not recommendation and cve_info.get("package_name"):
            pkg = cve_info["package_name"]
            fixed = cve_info.get("fixed_version") or "latest patched version"
            recommendation = f"Upgrade package {pkg} to {fixed}."

    gti_details_text = format_gti_enrichment(finding)

    return {
        "SUBJECT": subject_text,
        "WEB_LINK": console_url(finding.get("name")),
        "PROJECT_ID": esc(project),
        "RESOURCE": esc(resource_label),
        "SEVERITY": esc(severity),
        "SEV_EMO": SEVERITY_EMOJI.get(severity, ""),
        "STATE": esc(finding.get("state") or "n/a"),
        "TIMESTAMP": esc(finding.get("eventTime") or finding.get("createTime") or "n/a"),
        "CVE_DETAILS": cve_details_text,
        "GTI_DETAILS": gti_details_text,
        "EXPLANATION": esc(explanation),
        "RECOMMENDATION": esc(recommendation),
        # Quoted security mark names read better as inline code.
        "INSTRUCT": esc(instructions.replace('"', "`")) if instructions else None,
    }


def load_template():
    global _template_cache
    if _template_cache is None:
        with TEMPLATE_PATH.open("rt", encoding="utf-8") as fh:
            _template_cache = json.load(fh)
    return copy.deepcopy(_template_cache)


def _placeholders_in(obj):
    text = json.dumps(obj)
    return {key for key in PLACEHOLDER_KEYS if f"<{key}>" in text}


def _fill(obj, values):
    if isinstance(obj, dict):
        return {k: _fill(v, values) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_fill(v, values) for v in obj]
    if isinstance(obj, str):
        for key, value in values.items():
            obj = obj.replace(f"<{key}>", value or "")
        return obj
    return obj


def build_blocks(notification, template=None):
    """Return Slack blocks for the notification.

    Blocks that only exist to show a missing value are dropped, and every
    section text is kept within Slack's 3000 character limit.
    """
    template = template if template is not None else load_template()
    values = finding_values(notification)
    optional = {k for k, v in values.items() if v is None}

    blocks = []
    for block in template:
        if _placeholders_in(block) & optional:
            continue
        filled = _fill(block, values)
        text = filled.get("text")
        if isinstance(text, dict) and isinstance(text.get("text"), str):
            text["text"] = truncate(text["text"], SLACK_SECTION_TEXT_LIMIT)
        blocks.append(filled)
    return blocks


def fallback_text(notification):
    """Plain text used for push notifications and screen readers."""
    finding = notification.get("finding") or {}
    resource = notification.get("resource") or {}
    return (f"{finding.get('severity', 'New')} SCC finding "
            f"{finding.get('category', '')} in "
            f"{resource.get('projectDisplayName', 'unknown project')}")


# --------------------------------------------------------------------------
# Slack
# --------------------------------------------------------------------------

def post_to_slack(blocks, text, token, channel, session=requests):
    """Post a message. Raises TransientError or PermanentError on failure."""
    try:
        response = session.post(
            SLACK_API_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json; charset=utf-8",
            },
            data=json.dumps({
                "channel": channel,
                "blocks": blocks,
                "text": text,
                "unfurl_links": False,
                "unfurl_media": False,
            }),
            timeout=SLACK_TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise TransientError(f"Slack request failed: {exc}") from exc

    if response.status_code == 429 or response.status_code >= 500:
        raise TransientError(f"Slack returned HTTP {response.status_code}")
    try:
        body = response.json()
    except ValueError as exc:
        raise TransientError(f"Slack returned non JSON, HTTP {response.status_code}") from exc

    # Slack answers HTTP 200 for most errors, so the ok flag is authoritative.
    if not body.get("ok"):
        error = body.get("error", "unknown_error")
        detail = {"slack_error": error,
                  "response_metadata": body.get("response_metadata")}
        if error in TRANSIENT_SLACK_ERRORS:
            raise TransientError(f"Slack error {error}: {detail}")
        raise PermanentError(f"Slack error {error}: {detail}")
    return body


def handle_notification(notification, token=None, channel=None, session=requests):
    """Format and send one SCC notification. Returns False when skipped."""
    finding = notification.get("finding") or {}
    if not should_notify(notification):
        log("INFO", "Finding skipped by noise/project filter",
            finding=finding.get("name"))
        return False

    token = token or os.environ.get("SLACK_BOT_TOKEN")
    channel = channel or os.environ.get("SLACK_CHANNEL")
    if not token or not channel:
        raise PermanentError("SLACK_BOT_TOKEN and SLACK_CHANNEL must be set")

    post_to_slack(build_blocks(notification), fallback_text(notification),
                  token.strip(), channel, session=session)
    log("INFO", "Finding posted to Slack", finding=finding.get("name"),
        category=finding.get("category"),
        finding_severity=finding.get("severity"))
    return True


def _entry_point(cloud_event):
    max_age = int(os.environ.get("MAX_EVENT_AGE_SECONDS", "3600"))
    age = event_age_seconds(cloud_event["time"])
    if age is not None and age > max_age:
        log("ERROR", "Dropping event older than MAX_EVENT_AGE_SECONDS",
            event_id=cloud_event["id"], age_seconds=int(age))
        return

    try:
        notification = parse_pubsub_message(cloud_event.data)
        handle_notification(notification)
    except PermanentError as exc:
        # Acknowledge: retrying cannot fix this. Alert on this log line.
        log("ERROR", f"Permanent failure, event not retried: {exc}",
            event_id=cloud_event["id"])
    except TransientError as exc:
        log("WARNING", f"Transient failure, event will be retried: {exc}",
            event_id=cloud_event["id"])
        raise


if functions_framework is not None:
    send_slack_chat_notification = functions_framework.cloud_event(_entry_point)
else:
    send_slack_chat_notification = _entry_point


if __name__ == "__main__":
    # Local dry run: python main.py path/to/notification.json [--send]
    # Prints the Slack blocks. With --send it also posts them, using the
    # SLACK_BOT_TOKEN and SLACK_CHANNEL environment variables.
    if len(sys.argv) < 2:
        sys.exit("usage: python3 main.py <notification.json> [--send]")
    input_path = Path(sys.argv[1])
    if not input_path.exists():
        repo_root_candidate = Path(__file__).resolve().parents[2] / sys.argv[1]
        if repo_root_candidate.exists():
            input_path = repo_root_candidate
    with input_path.open("rt", encoding="utf-8") as fh:
        sample = json.load(fh)
    print(json.dumps(build_blocks(sample), indent=2, ensure_ascii=False))
    if "--send" in sys.argv[2:]:
        handle_notification(sample)
