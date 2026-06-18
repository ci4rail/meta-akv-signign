# meta-akv-signing

This layer adds Azure Key Vault backed HAB/imx-boot and FIT signing for
Toradex secure-boot builds. It builds `jepio/azure-keyvault-pkcs11` for the
native build environment and wires the Toradex HSM flow to Azure Key Vault
through OpenSSL's PKCS#11 engine.

The private keys remain in Azure Key Vault. The Yocto build receives only a
GitHub Actions OIDC identity, downloads the public certificates, and requests
remote signing operations.

## Provisioning Model

The layer supports one provisioning model:

- FIT, HAB CSF, and HAB IMG are Azure Key Vault certificate objects with
  associated private keys.
- Their certificate and key objects have matching names.
- The four HAB SRK CA certificates are local public build inputs.
- The SRK private keys remain offline.

For each configured `/keys/<name>` ID, the layer downloads the matching
`/certificates/<name>` object. The PKCS#11 provider exposes the downloaded FIT
certificate's public key to `mkimage` and exposes the CSF/IMG certificates to
NXP CST.

The Azure identity needs only these Key Vault data-plane permissions:

```json
[
  "Microsoft.KeyVault/vaults/keys/read",
  "Microsoft.KeyVault/vaults/keys/sign/action",
  "Microsoft.KeyVault/vaults/certificates/read"
]
```

It does not need secret access.

## Layer Setup

Add the layer to `BBLAYERS`, then configure the three Azure Key Vault key IDs
and exactly four local SRK certificates:

```bitbake
AKV_SIGNING_ENABLE = "1"

AZURE_FIT_KEY_ID = "https://vault-firmware-signing.vault.azure.net/keys/ci4rail-moducop-fit"
AKV_HAB_CSF_KEY_ID = "https://vault-firmware-signing.vault.azure.net/keys/ci4rail-moducop-csf"
AKV_HAB_IMG_KEY_ID = "https://vault-firmware-signing.vault.azure.net/keys/ci4rail-moducop-img"

AKV_HAB_SRK_CERT_FILES = "\
    /secure/srk1.der \
    /secure/srk2.der \
    /secure/srk3.der \
    /secure/srk4.der \
"
```

Key names become PKCS#11 labels automatically. Keep the FIT key name stable
because U-Boot stores it as the FIT signature's key-name hint.

The layer always uses HAB SRK CA mode. It generates the HAB SRK table and fuse
hash from the four local certificates, then uses the separate CSF and IMG
certificate-backed keys for signing.

## GitHub Actions OIDC

The build environment must provide:

```text
AZURE_TENANT_ID
AZURE_CLIENT_ID or AZURE_APP_ID
AZURE_FEDERATED_TOKEN_FILE
```

Only one client identifier is required. The `akv-signing` class maps
`AZURE_APP_ID` to `AZURE_CLIENT_ID` before invoking the certificate fetch helper
or CST wrapper because Azure workload identity uses `AZURE_CLIENT_ID`. The
GitHub Actions workflow currently passes both variables with the same value for
compatibility with the layer and with Azure Identity based tools.

`AZURE_SUBSCRIPTION_ID` is not required by this layer's certificate fetch or
signing path. It is passed through by the production kasfile and workflow, but
Key Vault data-plane certificate reads and signing requests are authorized by
the tenant, client ID, federated token, and Key Vault permissions.

`AZURE_AUTHORITY_HOST` is optional for public Azure. If it is unset, the helper
uses `https://login.microsoftonline.com`. Set it only when the build must use a
different Azure cloud authority.

For GitHub Actions, the build can either provide a pre-created federated token
file at `AZURE_FEDERATED_TOKEN_FILE`, or pass GitHub's OIDC request variables
so the layer can refresh that file before certificate fetches and CST signing:

```text
ACTIONS_ID_TOKEN_REQUEST_URL
ACTIONS_ID_TOKEN_REQUEST_TOKEN
```

The federated credential should be scoped to the repository and protected
GitHub environment used for firmware signing. The signing job needs:

```yaml
permissions:
  contents: read
  id-token: write
```

The OIDC token file and Azure identity variables must be mounted or passed into
the container that runs BitBake.

## Notes

`azure-keyvault-pkcs11` is a signing-oriented PKCS#11 implementation, not a
token-management provider. All three certificate-backed keys must already
exist in Azure Key Vault.
