#!/usr/bin/env python3
"""Fetch the public certificate associated with an Azure Key Vault key."""

import argparse
import base64
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request


TOKEN_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
VAULT_SCOPE = "https://vault.azure.net/.default"
API_VERSION = "7.4"


def env(name, fallback=None):
    value = os.environ.get(name) or fallback
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def certificate_url(key_id):
    parsed = urllib.parse.urlparse(key_id)
    parts = [part for part in parsed.path.split("/") if part]
    if parsed.scheme != "https" or len(parts) < 2 or parts[0] != "keys":
        raise SystemExit(
            f"Expected an Azure Key Vault key ID: {key_id}"
        )

    cert_parts = ["certificates", parts[1]]
    if len(parts) > 2:
        cert_parts.append(parts[2])
    return urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, "/" + "/".join(cert_parts), "", "", "")
    )


def request_json(url, data=None, headers=None):
    body = None
    if data is not None:
        body = urllib.parse.urlencode(data).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", "replace")
        raise SystemExit(f"HTTP {err.code} for {url}: {detail}") from err


def get_token():
    tenant_id = env("AZURE_TENANT_ID")
    client_id = os.environ.get("AZURE_CLIENT_ID") or env("AZURE_APP_ID")
    authority = os.environ.get("AZURE_AUTHORITY_HOST", "https://login.microsoftonline.com")
    token_file = env("AZURE_FEDERATED_TOKEN_FILE")

    with open(token_file, "r", encoding="utf-8") as handle:
        assertion = handle.read().strip()

    response = request_json(
        authority.rstrip("/") + f"/{tenant_id}/oauth2/v2.0/token",
        data={
            "client_id": client_id,
            "scope": VAULT_SCOPE,
            "grant_type": "client_credentials",
            "client_assertion_type": TOKEN_ASSERTION_TYPE,
            "client_assertion": assertion,
        },
    )
    return response["access_token"]


def decode_der(value):
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--key-id", required=True, help="Azure Key Vault key ID")
    parser.add_argument("--output", required=True, help="Output DER certificate path")
    args = parser.parse_args()

    url = certificate_url(args.key_id) + f"?api-version={API_VERSION}"
    response = request_json(url, headers={"Authorization": f"Bearer {get_token()}"})
    if "cer" not in response:
        raise SystemExit(f"Key Vault returned no certificate material for {args.key_id}")

    output_dir = os.path.dirname(args.output)
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
    with open(args.output, "wb") as handle:
        handle.write(decode_der(response["cer"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
