#!/usr/bin/env python3
"""Notify the configured Slack webhook after a production candidate is created."""
import http.client
import json
import os
import sys
import urllib.parse
import urllib.request

RUNBOOK = "https://github.com/LygosLabs/morpho-midnight-planning/blob/master/docs/production-tvc-yubikey-setup.md#releasing-dev-to-master"


def build_payload(env):
    required = (
        "GITHUB_SERVER_URL", "GITHUB_REPOSITORY", "GITHUB_RUN_ID", "GITHUB_SHA",
        "TVC_DEPLOYMENT_ID", "TVC_APP_ID", "TVC_MANIFEST_ID", "TVC_IMAGE",
        "TVC_EXECUTABLE_DIGEST",
    )
    if any(not env.get(key) for key in required):
        raise ValueError("missing release identity")
    repo_url = f"{env['GITHUB_SERVER_URL']}/{env['GITHUB_REPOSITORY']}"
    text = (
        "Production enclave release: awaiting 2-of-3 YubiKey approval (not live)\n"
        f"Repository: {env['GITHUB_REPOSITORY']}\n"
        f"Commit: {repo_url}/commit/{env['GITHUB_SHA']}\n"
        f"Actions: {repo_url}/actions/runs/{env['GITHUB_RUN_ID']}\n"
        "Turnkey: https://app.turnkey.com/tvc (select Lygos - Production)\n"
        f"App ID: {env['TVC_APP_ID']}\n"
        f"Deployment ID: {env['TVC_DEPLOYMENT_ID']}\n"
        f"Manifest ID: {env['TVC_MANIFEST_ID']}\n"
        f"Image: {env['TVC_IMAGE']}\n"
        f"Executable SHA-256: {env['TVC_EXECUTABLE_DIGEST']}\n\n"
        "Any two of Matt, Jay and Benny: verify this release, select your production "
        "CLI profile, and independently review/sign the manifest with your YubiKey:\n"
        f"tvc deploy approve --deploy-id {env['TVC_DEPLOYMENT_ID']} --serial <your-hex-serial>\n\n"
        "Then verify enclave attestation, re-encrypt/post your key shares, wait for "
        "all replicas to be ready, switch traffic and verify health. Keep the previous "
        "deployment available for rollback.\n"
        f"Runbook: {RUNBOOK}"
    )
    return {"text": text, "unfurl_links": False, "unfurl_media": False,
            "blocks": [{"type": "section", "text": {"type": "plain_text", "text": text}}]}


def main():
    webhook = os.environ.get("SLACK_WEBHOOK_URL", "")
    parsed = urllib.parse.urlparse(webhook)
    if parsed.scheme != "https" or parsed.hostname not in ("hooks.slack.com", "hooks.slack-gov.com"):
        print("::error::Configure SLACK_PRODUCTION_RELEASE_WEBHOOK_URL in the production GitHub environment. The deployment remains pending; see the Actions summary.")
        return 1
    try:
        payload = build_payload(os.environ)
        request = urllib.request.Request(webhook, data=json.dumps(payload).encode(),
                                         headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status != 200 or response.read().strip() != b"ok":
                raise ValueError("Slack rejected notification")
    except (ValueError, OSError, http.client.HTTPException):
        # Do not log exceptions: a request error could include the secret webhook URL.
        print("::error::Slack notification failed. The deployment remains pending; use the Actions summary for the approval handoff.")
        return 1
    print("Slack notified: production candidate awaiting 2-of-3 approval.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
