# meta-akv-signing

This layer adds Azure Key Vault backed HAB/imx-boot and FIT signing for
Toradex secure-boot builds. It builds `jepio/azure-keyvault-pkcs11` for the
native build environment and wires the Toradex HSM flow to Azure Key Vault
through OpenSSL's PKCS#11 engine.

The private key remains in Azure Key Vault. The Yocto build receives only an
OIDC-capable Azure identity and requests remote signing operations.

## Layer Setup

Add the layer to `BBLAYERS`, for example:

```bitbake
BBLAYERS += "${TOPDIR}/../src/meta-akv-signing"
```

Then enable Azure signing:

```bitbake
AKV_SIGNING_ENABLE = "1"

# HAB SRK keys. The local SRK table/fuse files must have been generated from
# the public certificates matching these Azure-held private keys.
AZURE_KEY_IDS = "\
    https://vault-firmware-signing.vault.azure.net/keys/ci4rail-moducop-g0 \
    https://vault-firmware-signing-2.vault.azure.net/keys/ci4rail-moducop-g1 \
    https://vault-firmware-signing-3.vault.azure.net/keys/ci4rail-moducop-g2 \
    https://vault-firmware-signing-4.vault.azure.net/keys/ci4rail-moducop-g3 \
"

# FIT uses a different key from HAB/imx-boot.
AZURE_FIT_KEY_ID = "https://vault-firmware-fit-signing.vault.azure.net/keys/ci4rail-moducop-fit"

AKV_HAB_SRK_LABELS = "ci4rail-moducop-g0 ci4rail-moducop-g1 ci4rail-moducop-g2 ci4rail-moducop-g3"
AKV_FIT_KEY_LABEL = "ci4rail-moducop-fit"
```

`AZURE_KEY_IDS` is rendered into the PKCS#11 configuration as four HAB SRK
slots. By default this layer configures direct SRK signing:

```bitbake
AKV_HAB_SRK_CA = "0"
```

With direct SRK signing, `TDX_IMX_HAB_CST_SRK_INDEX` selects which of the four
SRK slots is used for imx-boot signing.

If you use subordinate CSF/IMG keys instead, enable SRK CA mode and provide the
extra Azure keys:

```bitbake
AKV_HAB_SRK_CA = "1"
AKV_HAB_CSF_KEY_ID = "https://vault-firmware-signing.vault.azure.net/keys/ci4rail-moducop-csf"
AKV_HAB_IMG_KEY_ID = "https://vault-firmware-signing.vault.azure.net/keys/ci4rail-moducop-img"
AKV_HAB_CSF_KEY_LABEL = "ci4rail-moducop-csf"
AKV_HAB_IMG_KEY_LABEL = "ci4rail-moducop-img"
```

`azure-keyvault-pkcs11` can expose certificates from Key Vault certificate
objects. If the Azure objects are bare keys, CST still needs X.509 certificate
objects, so provide base64 DER certificates:

```bitbake
AKV_HAB_SRK_CERTIFICATES = "<srk1-der-base64> <srk2-der-base64> <srk3-der-base64> <srk4-der-base64>"
AKV_HAB_CSF_CERTIFICATE = "<csf-der-base64>"
AKV_HAB_IMG_CERTIFICATE = "<img-der-base64>"
```

The local `TDX_IMX_HAB_CST_SRK` and `TDX_IMX_HAB_CST_SRK_FUSE` files are still
used. They are public trust-anchor artifacts and must match the four Azure SRK
certificates.

## GitHub Actions OIDC

The layer expects Azure identity values from the environment:

```text
AZURE_SUBSCRIPTION_ID
AZURE_TENANT_ID
AZURE_APP_ID
AZURE_FEDERATED_TOKEN_FILE
```

`AZURE_APP_ID` is mapped to `AZURE_CLIENT_ID` before invoking `mkimage`, because
Azure Identity's workload identity credential expects `AZURE_CLIENT_ID`.

A GitHub Actions job should create the federated token file before starting the
Yocto build. The Azure application/service principal needs permission to perform
`sign` and public-key read/get operations on the configured keys.

## Notes

`azure-keyvault-pkcs11` is a signing-oriented PKCS#11 implementation, not a
full token-management provider. Keys must already exist in Azure Key Vault.

The `azure-sdk-cpp-native` recipe is intentionally narrow: it builds only the
Azure SDK components needed by the PKCS#11 provider.
