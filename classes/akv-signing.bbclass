# Azure Key Vault backed HAB/imx-boot and FIT signing through
# jepio/azure-keyvault-pkcs11.
#
# The layer.conf maps AKV_SIGNING_ENABLE to Toradex TDX_SIGNED_HSM on purpose:
# both CST and mkimage should use the same Azure PKCS#11 provider, but with
# distinct key labels.

AKV_SIGNING_ENABLE ?= "0"

# FIT uses a separate Azure key from HAB/imx-boot.
AZURE_FIT_KEY_ID ?= ""

# Labels become PKCS#11 token/object labels. Keep the FIT label short and stable:
# U-Boot stores UBOOT_SIGN_KEYNAME in the FIT signature node.
AKV_FIT_KEY_LABEL ?= "fit-signing-key"

# Optional public certificates. CST requires X.509 certificate objects.
AKV_HAB_SRK_CERTIFICATES ?= ""
AKV_HAB_CSF_CERTIFICATE ?= ""
AKV_HAB_IMG_CERTIFICATE ?= ""

# HAB SRK table/fuse generation. NXP srktool consumes X.509 certificates, not
# raw public keys, so provide either certificate files or base64 DER blobs.
AKV_HAB_GENERATE_SRK_TABLE ?= "1"
AKV_HAB_FETCH_SRK_CERTS ?= "1"
AKV_HAB_SRK_CERT_IDS ?= ""
AKV_HAB_SRK_CERT_FILES ?= ""
AKV_HAB_SRK_DIR ?= "${WORKDIR}/akv-srk"
AKV_HAB_SRK_TABLE ?= "${AKV_HAB_SRK_DIR}/SRK_1_2_3_4_table.bin"
AKV_HAB_SRK_FUSE ?= "${AKV_HAB_SRK_DIR}/SRK_1_2_3_4_fuse.bin"

# HAB is always configured in SRK CA mode: SRK certs are trust anchors, and
# separate CSF/IMG keys sign imx-boot.
AKV_HAB_CSF_KEY_ID ?= ""
AKV_HAB_IMG_KEY_ID ?= ""
AKV_HAB_CSF_KEY_LABEL ?= "hab-csf"
AKV_HAB_IMG_KEY_LABEL ?= "hab-img"

AKV_PKCS11_CONFIG_HOME ?= "${WORKDIR}/akv-signing"
AKV_PKCS11_MODULE_PATH ?= "${RECIPE_SYSROOT_NATIVE}${libdir}/pkcs11/azure-keyvault-pkcs11.so"
AKV_FETCH_CERT_TOOL ?= "${AKV_SIGNING_LAYERDIR}/scripts/akv-fetch-certificate.py"

DEPENDS:append = "${@bb.utils.contains('AKV_SIGNING_ENABLE', '1', ' azure-keyvault-pkcs11-native imx-code-signing-tool-native libp11-native openssl-native python3-native', '', d)}"

export XDG_CONFIG_HOME = "${AKV_PKCS11_CONFIG_HOME}"
export PKCS11_MODULE_PATH = "${AKV_PKCS11_MODULE_PATH}"
export AZURE_TENANT_ID
export AZURE_SUBSCRIPTION_ID
export AZURE_FEDERATED_TOKEN_FILE
export AZURE_AUTHORITY_HOST
export AZURE_CLIENT_ID = "${@akv_azure_client_id(d)}"

python __anonymous() {
    if d.getVar("AKV_SIGNING_ENABLE") == "1":
        d.setVar("TDX_SIGNED_HSM", "1")
        d.setVar("TDX_SIGNED_HSM_PKCS11_MODULE_PROVIDER", "azure-keyvault-pkcs11-native")
        d.setVar("TDX_SIGNED_HSM_PKCS11_MODULE_PATH", "${libdir}/pkcs11/azure-keyvault-pkcs11.so")
        if not d.getVar("TDX_SIGNED_HSM_TOKEN_PIN"):
            d.setVar("TDX_SIGNED_HSM_TOKEN_PIN", "unused")

        d.setVar("TDX_IMX_HAB_CST_SRK_CA", "1")
        if d.getVar("AKV_HAB_GENERATE_SRK_TABLE") == "1":
            d.setVar("TDX_IMX_HAB_CST_SRK", d.getVar("AKV_HAB_SRK_TABLE"))
            d.setVar("TDX_IMX_HAB_CST_SRK_FUSE", d.getVar("AKV_HAB_SRK_FUSE"))
        d.setVar("TDX_IMX_HAB_CST_CSF_CERT", akv_pkcs11_cert_uri(d.getVar("AKV_HAB_CSF_KEY_LABEL") or "hab-csf"))
        d.setVar("TDX_IMX_HAB_CST_IMG_CERT", akv_pkcs11_cert_uri(d.getVar("AKV_HAB_IMG_KEY_LABEL") or "hab-img"))

        d.setVar("TDX_SIGNED_HSM_FIT_TOKEN_URL", akv_pkcs11_key_uri(d.getVar("AKV_FIT_KEY_LABEL") or "fit-signing-key"))
        d.setVar("TDX_SIGNED_HSM_FIT_TOKEN_LABEL", d.getVar("AKV_FIT_KEY_LABEL") or "fit-signing-key")

        for task in ("do_assemble_fitimage", "do_assemble_fitimage_initramfs", "do_uboot_assemble_fitimage"):
            d.appendVarFlag(task, "prefuncs", " akv_signing_prepare")
        if d.getVar("PN") == "imx-boot":
            d.appendVarFlag("do_compile", "prefuncs", " akv_signing_prepare")
}

def akv_words(value):
    return (value or "").split()

def akv_pkcs11_key_uri(label):
    return "token=%s;object=%s" % (label, label)

def akv_pkcs11_cert_uri(label):
    return "pkcs11:token=%s;object=%s;type=cert" % (label, label)

def akv_azure_client_id(d):
    return d.getVar("AZURE_CLIENT_ID") or d.getVar("AZURE_APP_ID") or ""

akv_signing_prepare() {
    akv_config_dir="${AKV_PKCS11_CONFIG_HOME}/azure-keyvault-pkcs11"
    akv_config_file="${akv_config_dir}/config.json"
    akv_runtime_srk_cert_files="${AKV_HAB_SRK_CERT_FILES}"
    mkdir -p "${akv_config_dir}"

    akv_nth_word() {
        wanted="$1"
        shift
        idx=1
        for word in "$@"; do
            if [ "${idx}" = "${wanted}" ]; then
                printf '%s' "${word}"
                return 0
            fi
            idx=$((idx + 1))
        done
    }

    akv_fetch_srk_cert_files() {
        [ "${AKV_HAB_FETCH_SRK_CERTS}" = "1" ] || return 0
        [ -z "${AKV_HAB_SRK_CERTIFICATES}" ] || return 0
        [ -z "${akv_runtime_srk_cert_files}" ] || return 0
        [ -n "${AKV_HAB_SRK_CERT_IDS}" ] || return 0

        install -d "${AKV_HAB_SRK_DIR}/certs"
        idx=1
        fetched_files=""

        for cert_id in ${AKV_HAB_SRK_CERT_IDS}; do
            [ "${idx}" -le 4 ] || break
            cert_file="${AKV_HAB_SRK_DIR}/certs/srk${idx}.der"
            python3 "${AKV_FETCH_CERT_TOOL}" \
                --id "${cert_id}" \
                --output "${cert_file}" || bbfatal "Could not fetch public SRK certificate ${idx} from Azure Key Vault"
            if [ -n "${fetched_files}" ]; then
                fetched_files="${fetched_files} ${cert_file}"
            else
                fetched_files="${cert_file}"
            fi
            idx=$((idx + 1))
        done

        akv_runtime_srk_cert_files="${fetched_files}"
    }

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
    [ -n "${AKV_HAB_CSF_KEY_ID}" ] || bbfatal "AKV_SIGNING_ENABLE=1 requires AKV_HAB_CSF_KEY_ID"
    [ -n "${AKV_HAB_IMG_KEY_ID}" ] || bbfatal "AKV_SIGNING_ENABLE=1 requires AKV_HAB_IMG_KEY_ID"
    if [ -z "${AZURE_CLIENT_ID}" ]; then
        bbfatal "Missing Azure client id. Set AZURE_APP_ID or AZURE_CLIENT_ID in the environment."
    fi
    if [ -z "${AZURE_TENANT_ID}" ]; then
        bbfatal "Missing AZURE_TENANT_ID in the environment."
    fi
    if [ -z "${AZURE_FEDERATED_TOKEN_FILE}" ]; then
        bbfatal "Missing AZURE_FEDERATED_TOKEN_FILE. Configure GitHub Actions OIDC or provide another Azure Identity credential path."
    fi

    akv_fetch_srk_cert_files

    {
        printf '{\n  "slots": [\n'
    } > "${akv_config_file}"

    akv_sep=""
    printf '%s' "${akv_sep}" >> "${akv_config_file}"
    akv_emit_slot "${AZURE_FIT_KEY_ID}" "${AKV_FIT_KEY_LABEL}" ""
    akv_sep=",\n"

    printf "${akv_sep}" >> "${akv_config_file}"
    akv_emit_slot "${AKV_HAB_CSF_KEY_ID}" "${AKV_HAB_CSF_KEY_LABEL}" "${AKV_HAB_CSF_CERTIFICATE}"
    akv_sep=",\n"
    printf "${akv_sep}" >> "${akv_config_file}"
    akv_emit_slot "${AKV_HAB_IMG_KEY_ID}" "${AKV_HAB_IMG_KEY_LABEL}" "${AKV_HAB_IMG_CERTIFICATE}"

    printf '\n  ]\n}\n' >> "${akv_config_file}"

    akv_generate_srk_table() {
        [ "${AKV_HAB_GENERATE_SRK_TABLE}" = "1" ] || return 0

        srktool="${RECIPE_SYSROOT_NATIVE}${bindir}/srktool"
        if [ ! -x "${srktool}" ]; then
            srktool="${TDX_IMX_HAB_CST_DIR}/linux64/bin/srktool"
        fi
        [ -x "${srktool}" ] || bbfatal "srktool not found; cannot generate HAB SRK table/fuse files"

        install -d "${AKV_HAB_SRK_DIR}"

        if [ -n "${akv_runtime_srk_cert_files}" ]; then
            certs=""
            for cert_file in ${akv_runtime_srk_cert_files}; do
                [ -r "${cert_file}" ] || bbfatal "SRK certificate file is not readable: ${cert_file}"
                if [ -n "${certs}" ]; then
                    certs="${certs},${cert_file}"
                else
                    certs="${cert_file}"
                fi
            done
        elif [ -n "${AKV_HAB_SRK_CERTIFICATES}" ]; then
            certs=""
            idx=1
            for cert_b64 in ${AKV_HAB_SRK_CERTIFICATES}; do
                [ "${idx}" -le 4 ] || break
                cert_file="${AKV_HAB_SRK_DIR}/srk${idx}.der"
                printf '%s' "${cert_b64}" | base64 -d > "${cert_file}" || \
                    bbfatal "Could not decode AKV_HAB_SRK_CERTIFICATES entry ${idx}"
                if [ -n "${certs}" ]; then
                    certs="${certs},${cert_file}"
                else
                    certs="${cert_file}"
                fi
                idx=$((idx + 1))
            done
        else
            bbfatal "AKV_HAB_GENERATE_SRK_TABLE=1 requires AKV_HAB_SRK_CERT_IDS, AKV_HAB_SRK_CERT_FILES, or AKV_HAB_SRK_CERTIFICATES."
        fi

        cert_count="$(printf '%s' "${certs}" | tr ',' '\n' | sed '/^$/d' | wc -l)"
        [ "${cert_count}" = "4" ] || bbfatal "HAB SRK table generation requires exactly 4 SRK certificates, got ${cert_count}"

        "${srktool}" \
            --hab_ver 4 \
            --table "${AKV_HAB_SRK_TABLE}" \
            --efuses "${AKV_HAB_SRK_FUSE}" \
            --digest "${TDX_IMX_HAB_CST_DIG_ALGO}" \
            --certs "${certs}" || bbfatal "srktool failed while generating HAB SRK table/fuse files"
    }

    akv_generate_srk_table

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
}
