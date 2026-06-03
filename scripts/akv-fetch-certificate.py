#!/usr/bin/env python3
"""Fetch public SRK certificate material from Azure Key Vault for NXP srktool."""

import argparse
import base64
import json
import os
import sys
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


def derive_object_url(object_id):
    parsed = urllib.parse.urlparse(object_id)
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 2:
        raise SystemExit(f"Invalid Key Vault object id: {object_id}")

    kind = parts[0]
    name = parts[1]
    version = parts[2] if len(parts) > 2 and kind in ("certificates", "secrets") else ""
    if kind not in ("certificates", "keys", "secrets"):
        raise SystemExit(
            f"Expected a Key Vault key, certificate, or secret id: {object_id}"
        )

    object_kind = "certificates" if kind == "keys" else kind
    object_parts = [object_kind, name]
    if version:
        object_parts.append(version)
    url = urllib.parse.urlunparse(
        (parsed.scheme, parsed.netloc, "/" + "/".join(object_parts), "", "", "")
    )
    return kind, url


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

    token_url = authority.rstrip("/") + f"/{tenant_id}/oauth2/v2.0/token"
    response = request_json(
        token_url,
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
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded)
    except ValueError:
        return base64.urlsafe_b64decode(padded)


def cert_bytes_from_secret(value):
    if "-----BEGIN CERTIFICATE-----" in value:
        lines = [
            line.strip()
            for line in value.splitlines()
            if "CERTIFICATE" not in line and line.strip()
        ]
        return decode_der("".join(lines))
    return decode_der(value.strip())


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--id",
        required=True,
        help="Key Vault key/certificate id, or secret id containing PEM/base64 DER",
    )
    parser.add_argument("--output", required=True, help="Output DER certificate path")
    args = parser.parse_args()

    kind, object_url = derive_object_url(args.id)
    separator = "&" if "?" in object_url else "?"
    object_url = f"{object_url}{separator}api-version={API_VERSION}"

    token = get_token()
    response = request_json(object_url, headers={"Authorization": f"Bearer {token}"})
    if kind == "secrets":
        cert_bytes = cert_bytes_from_secret(response["value"])
    else:
        if "cer" not in response:
            raise SystemExit(
                "Key Vault returned no certificate material. Use a certificate "
                "object, a secret containing PEM/base64 DER, or provide "
                "AKV_HAB_SRK_CERT_FILES/AKV_HAB_SRK_CERTIFICATES."
            )
        cert_bytes = decode_der(response["cer"])

    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    with open(args.output, "wb") as handle:
        handle.write(cert_bytes)
    return 0


if __name__ == "__main__":
    sys.exit(main())
