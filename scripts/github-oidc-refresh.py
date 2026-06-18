#!/usr/bin/env python3
"""Refresh the GitHub Actions OIDC assertion used by Azure workload identity."""

import json
import os
import stat
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request


AUDIENCE = "api://AzureADTokenExchange"


def env(name):
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Missing required environment variable: {name}")
    return value


def token_path():
    path = env("AZURE_FEDERATED_TOKEN_FILE")
    if path.startswith("\\/"):
        path = path[1:]
    return path


def request_assertion():
    url = env("ACTIONS_ID_TOKEN_REQUEST_URL")
    separator = "&" if urllib.parse.urlparse(url).query else "?"
    request = urllib.request.Request(
        url + separator + urllib.parse.urlencode({"audience": AUDIENCE}),
        headers={"Authorization": f"Bearer {env('ACTIONS_ID_TOKEN_REQUEST_TOKEN')}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as err:
        detail = err.read().decode("utf-8", "replace")
        raise SystemExit(f"GitHub OIDC refresh failed with HTTP {err.code}: {detail}") from err

    assertion = data.get("value")
    if not assertion:
        raise SystemExit("GitHub OIDC response did not contain a value field")
    return assertion


def write_assertion(path, assertion):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".azure-federated-token.", dir=directory, text=True)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(assertion)
        os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temp_path, path)
    except Exception:
        try:
            os.unlink(temp_path)
        except FileNotFoundError:
            pass
        raise


def main():
    if not os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL") and not os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN"):
        return 0
    write_assertion(token_path(), request_assertion())
    return 0


if __name__ == "__main__":
    sys.exit(main())
