# Cloud Function code that listens to a Pub/Sub Topic, where the Security Command Center API publishes messages 
# about Findings with a critical and high severity. 
# The Cloud Function code picks up the message and publish it to a Slack channel #security-gcp-alerts”.
# Runtime: Python 3.8 and the Entrypoint should be defined as: send_slack_chat_notification

import base64
import json
import os
import time
import requests

from google.cloud import logging
from google.cloud import secretmanager

# Configurable thresholds for CVE filtering and deduplication to reduce Slack noise
ALLOWED_EXPLOITABILITY = {
    x.strip().upper()
    for x in os.environ.get("ALLOWED_EXPLOITABILITY", "WIDE,AVAILABLE,CONFIRMED").split(",")
    if x.strip()
}
ALLOWED_CVE_IMPACT = {
    x.strip().upper()
    for x in os.environ.get("ALLOWED_CVE_IMPACT", "CRITICAL,HIGH").split(",")
    if x.strip()
}
REQUIRE_UPSTREAM_FIX = os.environ.get("REQUIRE_UPSTREAM_FIX", "false").lower() == "true"
DEDUP_WINDOW_SECONDS = int(os.environ.get("DEDUP_WINDOW_SECONDS", "3600"))

# In-memory deduplication cache across warm Cloud Function invocations (max_instances=1)
# Maps dedup_key -> last_sent_epoch_timestamp
_RECENT_ALERTS_CACHE = {}


def get_secret(secret_id="sccnotifier-slack-bot-token", version_id="latest"):
    client = secretmanager.SecretManagerServiceClient()
    # Prefer the full secret version resource path injected by Terraform in SLACK_BOT_TOKEN
    secret_env = os.environ.get("SLACK_BOT_TOKEN", "")
    if secret_env.startswith("projects/"):
        name = secret_env
    else:
        project_id = os.environ.get("GCP_PROJECT_ID", "[INSERT-PROJECT-ID]")
        name = f"projects/{project_id}/secrets/{secret_id}/versions/{version_id}"
    request = secretmanager.AccessSecretVersionRequest(name=name)
    return client.access_secret_version(request=request).payload.data.decode("utf-8").strip()


def extract_cve_details(finding):
    """Extracts normalized CVE risk metadata from an SCC finding if a CVE is present."""
    vulnerability = finding.get("vulnerability") or {}
    cve = vulnerability.get("cve") or {}
    cve_id = cve.get("id")
    if not cve_id:
        return None

    cvssv3 = cve.get("cvssv3") or {}
    packages = vulnerability.get("offendingPackage") or {}
    fixed_pkg = vulnerability.get("fixedPackage") or {}

    return {
        "is_vulnerability": True,
        "cve_id": cve_id or finding.get("category", "UNKNOWN_CVE"),
        "exploitation_activity": str(cve.get("exploitationActivity", "NO_KNOWN")).upper(),
        "impact": str(cve.get("impact", "RISK_RATING_UNSPECIFIED")).upper(),
        "observed_in_the_wild": bool(cve.get("observedInTheWild", False)),
        "zero_day": bool(cve.get("zeroDay", False)),
        "upstream_fix_available": bool(cve.get("upstreamFixAvailable", False)),
        "cvss_score": cvssv3.get("baseScore"),
        "package_name": packages.get("packageName"),
        "package_version": packages.get("cpeUri") or packages.get("version"),
        "fixed_version": fixed_pkg.get("version") or fixed_pkg.get("cpeUri"),
    }


def should_alert(payload):
    """
    Validates whether an SCC finding should trigger a Slack notification.
    Returns (bool, reason_string).
    """
    finding = payload.get("finding") or {}
    resource = payload.get("resource") or {}

    state = str(finding.get("state", "")).upper()
    if state != "ACTIVE":
        return False, f"Skipped inactive finding (state={state})"

    severity = str(finding.get("severity", "")).upper()
    if severity not in {"CRITICAL", "HIGH"}:
        return False, f"Skipped low/medium finding (severity={severity})"

    cve_info = extract_cve_details(finding)
    if cve_info is not None:
        exploitability = cve_info["exploitation_activity"]
        impact = cve_info["impact"]

        # Check exploitability (must be WIDE or AVAILABLE / CONFIRMED, or actively observedInTheWild/zeroDay)
        is_exploitable = (
            exploitability in ALLOWED_EXPLOITABILITY
            or cve_info["observed_in_the_wild"]
            or cve_info["zero_day"]
        )
        if not is_exploitable:
            return (
                False,
                f"Skipped CVE {cve_info['cve_id']}: exploitability='{exploitability}' not in {sorted(ALLOWED_EXPLOITABILITY)}",
            )

        # Check CVE impact (must be CRITICAL or HIGH)
        if impact not in ALLOWED_CVE_IMPACT:
            return (
                False,
                f"Skipped CVE {cve_info['cve_id']}: impact='{impact}' not in {sorted(ALLOWED_CVE_IMPACT)}",
            )

        if REQUIRE_UPSTREAM_FIX and not cve_info["upstream_fix_available"]:
            return (
                False,
                f"Skipped CVE {cve_info['cve_id']}: no upstream fix available yet",
            )

        # Deduplicate repeated alerts for the same CVE across the WHOLE organization within DEDUP_WINDOW_SECONDS
        name_parts = finding.get("name", "organizations/org").split("/")
        org_id = name_parts[1] if len(name_parts) > 1 else "org"
        dedup_key = f"org::{org_id}::{cve_info['cve_id']}"
        now = time.time()
        last_sent = _RECENT_ALERTS_CACHE.get(dedup_key)
        if last_sent and (now - last_sent) < DEDUP_WINDOW_SECONDS:
            return (
                False,
                f"Suppressed duplicate organization-wide CVE alert for {dedup_key} (cooldown {DEDUP_WINDOW_SECONDS}s)",
            )
        _RECENT_ALERTS_CACHE[dedup_key] = now

    return True, "Alert matched criteria"


def message_post(data):
    payload = data if isinstance(data, dict) else json.loads(data)

    allowed, reason = should_alert(payload)
    if not allowed:
        print(f"[NOISE-FILTER] {reason}")
        return False

    token = str(get_secret("sccnotifier-slack-bot-token"))
    channel_id = os.environ.get("SLACK_CHANNEL", "security-gcp-alerts")

    url = "https://slack.com/api/chat.postMessage"
    headers = {
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json; charset=utf-8",
    }
    try:
        template_path = os.path.join(
            os.path.dirname(__file__), "block_templates", "finding-detail.json"
        )
        with open(template_path, "rt") as block_f:
            block_template = json.load(block_f)

        merge_template(block_template, payload)

        params = {
            "channel": channel_id,
            "blocks": block_template,
            "text": "High-Priority Security Command Center Alert",
            "unfurl_links": "false",
        }
        r = requests.post(url, data=json.dumps(params), headers=headers, timeout=15)
        if r.status_code != 200:
            raise ValueError(
                f"Request to Slack returned error {r.status_code}. Response is: {r.text}"
            )
        return True

    except Exception as e:
        print(f"Error occurred attempting to post message. Error is: {e}")
        return False


def merge_template(list_data, payload):
    finding = payload.get("finding") or {}
    resource = payload.get("resource") or {}
    props = finding.get("sourceProperties") or {}
    cve_info = extract_cve_details(finding)

    name_parts = finding.get("name", "organizations/0/sources/0/findings/0").split("/")
    org_id = name_parts[1] if len(name_parts) > 1 else "0"
    source_id = name_parts[3] if len(name_parts) > 3 else "0"
    finding_id = name_parts[-1]
    severity = str(finding.get("severity", "UNKNOWN")).upper()

    if severity == "CRITICAL":
        sev_emo = ":rotating_light:"
    elif "HIGH" in severity:
        sev_emo = ":warning:"
    else:
        sev_emo = ":information_source:"

    url = "https://console.cloud.google.com/security/command-center/findings"
    url += f"?organizations/{org_id}/sources/{source_id}/"
    url += f"findings/{finding_id}=,true&orgonly=true"
    url += f"&organizationId={org_id}&supportedpurview=organizationId"
    url += "&view_type=vt_finding_type&vt_finding_type=All"
    url += f"&resourceId=organizations/{org_id}/sources/{source_id}/"
    url += f"findings/{finding_id}"

    if cve_info:
        cve_id = cve_info["cve_id"]
        exploit = cve_info["exploitation_activity"]
        impact = cve_info["impact"]
        alert_badge = (
            f":rotating_light: *[{exploit} EXPLOIT | {impact} IMPACT]*"
            if exploit == "WIDE" or impact == "CRITICAL"
            else f":warning: *[{exploit} EXPLOIT | {impact} IMPACT]*"
        )
        subject = f"{cve_id} ({finding.get('category', 'VULNERABILITY')})"
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        org_cve_url = (
            f"https://console.cloud.google.com/security/command-center/findings"
            f"?organizationId={org_id}&supportedpurview=organizationId&vt_finding_type=All"
        )
        cvss_str = str(cve_info["cvss_score"]) if cve_info["cvss_score"] is not None else "N/A"
        fix_str = "Yes :white_check_mark:" if cve_info["upstream_fix_available"] else "No :x:"
        wild_flags = []
        if cve_info["observed_in_the_wild"]:
            wild_flags.append("Observed in the Wild")
        if cve_info["zero_day"]:
            wild_flags.append("Zero-Day")
        wild_suffix = f" ({', '.join(wild_flags)})" if wild_flags else ""

        cve_context = (
            f"\n*CVE*: <{nvd_url}|{cve_id}> (<{org_cve_url}|View All Affected Org Resources>)"
            f"\n*Exploitability*: *{exploit}*{wild_suffix} | *Impact*: *{impact}*"
            f"\n*CVSSv3*: `{cvss_str}` | *Upstream Fix*: {fix_str}"
        )
    else:
        alert_badge = ":rotating_light:" if severity == "CRITICAL" else ":warning:"
        subject = finding.get("category", "SECURITY_FINDING")
        cve_context = ""

    list_data[0]["text"]["text"] = (
        list_data[0]["text"]["text"]
        .replace("<ALERT_BADGE>", alert_badge)
        .replace("<SUBJECT>", subject)
        .replace("<WEB_LINK>", url)
    )

    list_data[1]["text"]["text"] = (
        list_data[1]["text"]["text"]
        .replace("<ORG_ID>", str(org_id))
        .replace("<PROJECT_ID>", str(resource.get("projectDisplayName", "Unknown")))
        .replace("<SEVERITY>", severity)
        .replace("<SEV_EMO>", sev_emo)
        .replace("<CVE_CONTEXT>", cve_context)
        .replace("<STATE>", str(finding.get("state", "ACTIVE")))
        .replace("<TIMESTAMP>", str(finding.get("createTime", "N/A")))
    )

    list_data[1]["accessory"]["url"] = list_data[1]["accessory"]["url"].replace(
        "<WEB_LINK>", url
    )

    default_explanation = (
        f"Exploitable vulnerability {cve_info['cve_id']} detected on resource `{finding.get('resourceName', 'N/A')}`."
        if cve_info
        else "See Cloud Console for finding details."
    )
    explain = format_text(
        json.dumps(props.get("Explanation") or default_explanation), False
    )
    list_data[2]["text"]["text"] = list_data[2]["text"]["text"].replace(
        "<EXPLANATION>", explain
    )

    default_recommendation = (
        f"Upgrade package `{cve_info.get('package_name') or 'affected component'}` to `{cve_info.get('fixed_version') or 'latest patched version'}`."
        if cve_info
        else "Review remediation steps in Security Command Center."
    )
    recommend = format_text(
        json.dumps(props.get("Recommendation") or default_recommendation), False
    )
    list_data[3]["text"]["text"] = list_data[3]["text"]["text"].replace(
        "<RECOMMENDATION>", recommend
    )

    default_instruct = (
        "Prioritize patching immediately due to active/available exploitability and high/critical impact."
        if cve_info
        else "Follow organization exception handling workflow if applicable."
    )
    instr = format_text(
        json.dumps(props.get("ExceptionInstructions") or default_instruct), True
    )
    list_data[4]["text"]["text"] = list_data[4]["text"]["text"].replace(
        "<INSTRUCT>", instr
    )


def format_text(val, text2CodeBlocks: bool = False):
    val = val.replace("\\", "")
    val = val[1:] if val.startswith('"') else val
    val = val[:-1] if val.endswith('"') else val
    if text2CodeBlocks is True:
        val = val.replace('"', "`")
    return val


def send_slack_chat_notification(event, context):
    CUSTOM_LOG_NAME = "scc_notifications_log"
    logging_client = logging.Client()
    logger = logging_client.logger(CUSTOM_LOG_NAME)

    try:
        payload = base64.b64decode(event["data"]).decode("utf-8")
        message_post(payload)
    except Exception as e:
        logger.log_text(f"Error processing SCC notification: {e}", severity="ERROR")


if __name__ == "__main__":
    test_path = os.path.join(os.path.dirname(__file__), "payload_test.json")
    with open(test_path, "rt") as testdata_f:
        testdata = json.load(testdata_f)
    message_post(testdata)