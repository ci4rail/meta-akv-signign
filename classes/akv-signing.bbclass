# Azure Key Vault backed HAB/imx-boot and FIT signing through
# jepio/azure-keyvault-pkcs11.
#
# The layer.conf maps AKV_SIGNING_ENABLE to Toradex TDX_SIGNED_HSM on purpose:
# both CST and mkimage should use the same Azure PKCS#11 provider, but with
# distinct key labels.

AKV_SIGNING_ENABLE ?= "0"

# Space-separated Azure Key Vault key identifiers for HAB SRKs. These can be
# split across lines in configuration files. The public certificates for these
# keys must match TDX_IMX_HAB_CST_SRK and TDX_IMX_HAB_CST_SRK_FUSE.
AZURE_KEY_IDS ?= ""
AZURE_HAB_SRK_KEY_IDS ?= "${AZURE_KEY_IDS}"
AZURE_FIT_KEY_ID ?= ""

# Labels become PKCS#11 token/object labels. Keep them short and stable:
# U-Boot stores UBOOT_SIGN_KEYNAME in the FIT signature node.
AKV_HAB_SRK_LABELS ?= "hab-srk1 hab-srk2 hab-srk3 hab-srk4"
AKV_FIT_KEY_LABEL ?= "fit-signing-key"

# Optional inline/base64 DER certificates. CST requires X.509 certificate
# objects. If the Azure keys are bare Key Vault keys, provide the matching
# certificates here; if the Azure object is a Key Vault certificate with an
# associated private key, the provider may expose it without inline cert data.
AKV_HAB_SRK_CERTIFICATES ?= ""
AKV_HAB_CSF_CERTIFICATE ?= ""
AKV_HAB_IMG_CERTIFICATE ?= ""

# Default to direct SRK signing because the user-provided configuration names
# four HAB SRKs. Set this to "1" when using subordinate CSF/IMG signing keys.
AKV_HAB_SRK_CA ?= "0"
AKV_HAB_CSF_KEY_ID ?= ""
AKV_HAB_IMG_KEY_ID ?= ""
AKV_HAB_CSF_KEY_LABEL ?= "hab-csf"
AKV_HAB_IMG_KEY_LABEL ?= "hab-img"

AKV_PKCS11_CONFIG_HOME ?= "${WORKDIR}/akv-signing"
AKV_PKCS11_MODULE_PATH ?= "${RECIPE_SYSROOT_NATIVE}${libdir}/pkcs11/azure-keyvault-pkcs11.so"

DEPENDS:append = "${@bb.utils.contains('AKV_SIGNING_ENABLE', '1', ' azure-keyvault-pkcs11-native libp11-native openssl-native', '', d)}"

export XDG_CONFIG_HOME = "${AKV_PKCS11_CONFIG_HOME}"
export PKCS11_MODULE_PATH = "${AKV_PKCS11_MODULE_PATH}"
export AZURE_TENANT_ID
export AZURE_SUBSCRIPTION_ID
export AZURE_FEDERATED_TOKEN_FILE
export AZURE_AUTHORITY_HOST
export AZURE_CLIENT_ID = "${@akv_azure_client_id(d)}"

python __anonymous() {
    if d.getVar("AKV_SIGNING_ENABLE") == "1":
        hab_labels = akv_words(d.getVar("AKV_HAB_SRK_LABELS"))
        srk_index = int(d.getVar("TDX_IMX_HAB_CST_SRK_INDEX") or "1")
        if srk_index < 1 or srk_index > 4:
            bb.fatal("TDX_IMX_HAB_CST_SRK_INDEX must be in the range 1..4")
        hab_label = hab_labels[srk_index - 1] if srk_index <= len(hab_labels) else "hab-srk%d" % srk_index

        d.setVar("TDX_SIGNED_HSM", "1")
        d.setVar("TDX_SIGNED_HSM_PKCS11_MODULE_PROVIDER", "azure-keyvault-pkcs11-native")
        d.setVar("TDX_SIGNED_HSM_PKCS11_MODULE_PATH", "${libdir}/pkcs11/azure-keyvault-pkcs11.so")
        if not d.getVar("TDX_SIGNED_HSM_TOKEN_PIN"):
            d.setVar("TDX_SIGNED_HSM_TOKEN_PIN", "unused")

        d.setVar("TDX_IMX_HAB_CST_SRK_CA", d.getVar("AKV_HAB_SRK_CA") or "0")
        d.setVar("TDX_IMX_HAB_CST_SRK_CERT", akv_pkcs11_cert_uri(hab_label))
        if d.getVar("AKV_HAB_SRK_CA") == "1":
            d.setVar("TDX_IMX_HAB_CST_CSF_CERT", akv_pkcs11_cert_uri(d.getVar("AKV_HAB_CSF_KEY_LABEL") or "hab-csf"))
            d.setVar("TDX_IMX_HAB_CST_IMG_CERT", akv_pkcs11_cert_uri(d.getVar("AKV_HAB_IMG_KEY_LABEL") or "hab-img"))

        d.setVar("TDX_SIGNED_HSM_FIT_TOKEN_URL", akv_pkcs11_key_uri(d.getVar("AKV_FIT_KEY_LABEL") or "fit-signing-key"))
        d.setVar("TDX_SIGNED_HSM_FIT_TOKEN_LABEL", d.getVar("AKV_FIT_KEY_LABEL") or "fit-signing-key")

        for task in ("do_assemble_fitimage", "do_assemble_fitimage_initramfs", "do_uboot_assemble_fitimage"):
            d.appendVarFlag(task, "prefuncs", " akv_signing_prepare")
}

def akv_words(value):
    return (value or "").split()

def akv_first_key_id(d):
    ids = akv_words(d.getVar("AZURE_KEY_IDS"))
    return ids[0] if ids else ""

def akv_pkcs11_key_uri(label):
    return "token=%s;object=%s" % (label, label)

def akv_pkcs11_cert_uri(label):
    return "pkcs11:token=%s;object=%s;type=cert" % (label, label)

def akv_azure_client_id(d):
    return d.getVar("AZURE_CLIENT_ID") or d.getVar("AZURE_APP_ID") or ""

akv_signing_prepare() {
    akv_config_dir="${AKV_PKCS11_CONFIG_HOME}/azure-keyvault-pkcs11"
    akv_config_file="${akv_config_dir}/config.json"
    mkdir -p "${akv_config_dir}"

    akv_emit_slot() {
        key_id="$1"
        label="$2"
        certificate="$3"

        case "${key_id}" in
            https://*/keys/*) ;;
            *) bbfatal "Invalid Azure Key Vault key id: ${key_id}" ;;
        esac

        rest="${key_id#https://}"
        host="${rest%%/*}"
        path="${rest#*/}"
        path="${path#keys/}"
        key_name="${path%%/*}"
        vault_url="https://${host}/"

        if [ -n "${certificate}" ]; then
            printf '    {"label": "%s", "key_name": "%s", "vault_url": "%s", "certificate": "%s"}' \
                "${label}" "${key_name}" "${vault_url}" "${certificate}" >> "${akv_config_file}"
        else
            printf '    {"label": "%s", "key_name": "%s", "vault_url": "%s"}' \
                "${label}" "${key_name}" "${vault_url}" >> "${akv_config_file}"
        fi
    }

    [ -n "${AZURE_FIT_KEY_ID}" ] || bbfatal "AKV_SIGNING_ENABLE=1 requires AZURE_FIT_KEY_ID for FIT signing"
    [ -n "${AZURE_HAB_SRK_KEY_IDS}" ] || bbfatal "AKV_SIGNING_ENABLE=1 requires AZURE_HAB_SRK_KEY_IDS or AZURE_KEY_IDS for HAB signing"

    {
        printf '{\n  "slots": [\n'
    } > "${akv_config_file}"

    akv_sep=""
    printf '%s' "${akv_sep}" >> "${akv_config_file}"
    akv_emit_slot "${AZURE_FIT_KEY_ID}" "${AKV_FIT_KEY_LABEL}" ""
    akv_sep=",\n"

    akv_idx=1
    set -- ${AKV_HAB_SRK_LABELS}
    for key_id in ${AZURE_HAB_SRK_KEY_IDS}; do
        [ "${akv_idx}" -le 4 ] || break
        case "${akv_idx}" in
            1) label="$1"; certificate="$(printf '%s\n' ${AKV_HAB_SRK_CERTIFICATES} | sed -n '1p')" ;;
            2) label="$2"; certificate="$(printf '%s\n' ${AKV_HAB_SRK_CERTIFICATES} | sed -n '2p')" ;;
            3) label="$3"; certificate="$(printf '%s\n' ${AKV_HAB_SRK_CERTIFICATES} | sed -n '3p')" ;;
            4) label="$4"; certificate="$(printf '%s\n' ${AKV_HAB_SRK_CERTIFICATES} | sed -n '4p')" ;;
        esac
        [ -n "${label}" ] || label="hab-srk${akv_idx}"
        printf "${akv_sep}" >> "${akv_config_file}"
        akv_emit_slot "${key_id}" "${label}" "${certificate}"
        akv_sep=",\n"
        akv_idx=$((akv_idx + 1))
    done

    if [ "${AKV_HAB_SRK_CA}" = "1" ]; then
        [ -n "${AKV_HAB_CSF_KEY_ID}" ] || bbfatal "AKV_HAB_SRK_CA=1 requires AKV_HAB_CSF_KEY_ID"
        [ -n "${AKV_HAB_IMG_KEY_ID}" ] || bbfatal "AKV_HAB_SRK_CA=1 requires AKV_HAB_IMG_KEY_ID"
        printf "${akv_sep}" >> "${akv_config_file}"
        akv_emit_slot "${AKV_HAB_CSF_KEY_ID}" "${AKV_HAB_CSF_KEY_LABEL}" "${AKV_HAB_CSF_CERTIFICATE}"
        akv_sep=",\n"
        printf "${akv_sep}" >> "${akv_config_file}"
        akv_emit_slot "${AKV_HAB_IMG_KEY_ID}" "${AKV_HAB_IMG_KEY_LABEL}" "${AKV_HAB_IMG_CERTIFICATE}"
    fi

    printf '\n  ]\n}\n' >> "${akv_config_file}"

    for d in \
        "${RECIPE_SYSROOT_NATIVE}${libdir}/engines-3" \
        "${RECIPE_SYSROOT_NATIVE}${libdir}/engines-1.1"
    do
        if [ -d "$d" ]; then
            export OPENSSL_ENGINES="$d"
            break
        fi
    done

    [ -n "${OPENSSL_ENGINES}" ] || bbfatal "OpenSSL engines directory not found in native sysroot"
    [ -r "${PKCS11_MODULE_PATH}" ] || bbfatal "Azure Key Vault PKCS#11 module missing or not readable: ${PKCS11_MODULE_PATH}"

    if [ -z "${AZURE_CLIENT_ID}" ]; then
        bbfatal "Missing Azure client id. Set AZURE_APP_ID or AZURE_CLIENT_ID in the environment."
    fi
    if [ -z "${AZURE_TENANT_ID}" ]; then
        bbfatal "Missing AZURE_TENANT_ID in the environment."
    fi
    if [ -z "${AZURE_FEDERATED_TOKEN_FILE}" ]; then
        bbfatal "Missing AZURE_FEDERATED_TOKEN_FILE. Configure GitHub Actions OIDC or provide another Azure Identity credential path."
    fi
}
