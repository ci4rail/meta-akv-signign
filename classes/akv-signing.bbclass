# Azure Key Vault backed HAB/imx-boot and FIT signing through
# jepio/azure-keyvault-pkcs11.
#
# CSF, IMG, and FIT must each be an Azure Key Vault certificate with an
# associated private key. The configured key IDs identify both the signing
# keys and their matching public certificates.

AKV_SIGNING_ENABLE ?= "0"

AZURE_FIT_KEY_ID ?= ""
AKV_HAB_CSF_KEY_ID ?= ""
AKV_HAB_IMG_KEY_ID ?= ""

# NXP srktool requires exactly four local X.509 SRK CA certificates.
AKV_HAB_SRK_CERT_FILES ?= ""

AKV_HAB_SRK_DIR = "${WORKDIR}/akv-srk"
AKV_HAB_SRK_TABLE = "${AKV_HAB_SRK_DIR}/SRK_1_2_3_4_table.bin"
AKV_HAB_SRK_FUSE = "${AKV_HAB_SRK_DIR}/SRK_1_2_3_4_fuse.bin"
AKV_PKCS11_CONFIG_HOME = "${WORKDIR}/akv-signing"
AKV_PKCS11_MODULE_PATH = "${RECIPE_SYSROOT_NATIVE}${libdir}/pkcs11/azure-keyvault-pkcs11.so"
AKV_FETCH_CERT_TOOL = "${AKV_SIGNING_LAYERDIR}/scripts/akv-fetch-certificate.py"

DEPENDS:append = "${@bb.utils.contains('AKV_SIGNING_ENABLE', '1', ' azure-keyvault-pkcs11-native imx-code-signing-tool-native libp11-native openssl-native python3-native', '', d)}"

export XDG_CONFIG_HOME = "${AKV_PKCS11_CONFIG_HOME}"
export PKCS11_MODULE_PATH = "${AKV_PKCS11_MODULE_PATH}"
export AZURE_TENANT_ID
export AZURE_SUBSCRIPTION_ID
export AZURE_FEDERATED_TOKEN_FILE
export AZURE_AUTHORITY_HOST
AZURE_CLIENT_ID ?= "${AZURE_APP_ID}"
export AZURE_CLIENT_ID

python __anonymous() {
    if d.getVar("AKV_SIGNING_ENABLE") == "1":
        fit_label = akv_key_name(d.getVar("AZURE_FIT_KEY_ID"), "AZURE_FIT_KEY_ID")
        csf_label = akv_key_name(d.getVar("AKV_HAB_CSF_KEY_ID"), "AKV_HAB_CSF_KEY_ID")
        img_label = akv_key_name(d.getVar("AKV_HAB_IMG_KEY_ID"), "AKV_HAB_IMG_KEY_ID")

        d.setVar("TDX_SIGNED_HSM", "1")
        d.setVar("TDX_SIGNED_HSM_PKCS11_MODULE_PROVIDER", "azure-keyvault-pkcs11-native")
        d.setVar("TDX_SIGNED_HSM_PKCS11_MODULE_PATH", "${libdir}/pkcs11/azure-keyvault-pkcs11.so")
        if not d.getVar("TDX_SIGNED_HSM_TOKEN_PIN"):
            d.setVar("TDX_SIGNED_HSM_TOKEN_PIN", "unused")

        d.setVar("TDX_IMX_HAB_CST_SRK_CA", "1")
        d.setVar("TDX_IMX_HAB_CST_SRK", d.getVar("AKV_HAB_SRK_TABLE"))
        d.setVar("TDX_IMX_HAB_CST_SRK_FUSE", d.getVar("AKV_HAB_SRK_FUSE"))
        d.setVar("TDX_IMX_HAB_CST_CSF_CERT", akv_pkcs11_cert_uri(csf_label))
        d.setVar("TDX_IMX_HAB_CST_IMG_CERT", akv_pkcs11_cert_uri(img_label))

        d.setVar("TDX_SIGNED_HSM_FIT_TOKEN_URL", akv_pkcs11_key_uri(fit_label))
        d.setVar("TDX_SIGNED_HSM_FIT_TOKEN_LABEL", fit_label)

        for task in ("do_assemble_fitimage", "do_assemble_fitimage_initramfs", "do_uboot_assemble_fitimage"):
            d.appendVarFlag(task, "prefuncs", " akv_signing_prepare")
        if d.getVar("PN") == "imx-boot":
            d.appendVarFlag("do_compile", "prefuncs", " akv_signing_prepare")
}

def akv_key_name(key_id, variable):
    parts = (key_id or "").split("/")
    if len(parts) < 5 or parts[0] != "https:" or parts[2] == "" or parts[3] != "keys" or parts[4] == "":
        bb.fatal("%s must be an Azure Key Vault key ID: https://<vault>/keys/<name>[/<version>]" % variable)
    return parts[4]

def akv_pkcs11_key_uri(label):
    return "token=%s;object=%s" % (label, label)

def akv_pkcs11_cert_uri(label):
    return "pkcs11:token=%s;object=%s;type=cert" % (label, label)

akv_signing_prepare() {
    akv_config_dir="${AKV_PKCS11_CONFIG_HOME}/azure-keyvault-pkcs11"
    akv_config_file="${akv_config_dir}/config.json"
    akv_cert_dir="${AKV_PKCS11_CONFIG_HOME}/certificates"
    install -d "${akv_config_dir}" "${akv_cert_dir}" "${AKV_HAB_SRK_DIR}"

    akv_key_name() {
        key_id="$1"
        rest="${key_id#https://}"
        path="${rest#*/}"
        path="${path#keys/}"
        printf '%s' "${path%%/*}"
    }

    akv_fetch_certificate() {
        key_id="$1"
        output="$2"
        python3 "${AKV_FETCH_CERT_TOOL}" --key-id "${key_id}" --output "${output}" || \
            bbfatal "Could not fetch the certificate matching Azure Key Vault key ${key_id}"
    }

    akv_emit_slot() {
        key_id="$1"
        certificate_file="$2"
        rest="${key_id#https://}"
        host="${rest%%/*}"
        key_name="$(akv_key_name "${key_id}")"
        certificate="$(base64 < "${certificate_file}" | tr -d '\n')"

        printf '    {"label": "%s", "key_name": "%s", "vault_url": "https://%s/", "certificate": "%s"}' \
            "${key_name}" "${key_name}" "${host}" "${certificate}"
    }

    [ -n "${AZURE_CLIENT_ID}" ] || bbfatal "Missing Azure client id. Set AZURE_APP_ID or AZURE_CLIENT_ID in the environment."
    [ -n "${AZURE_TENANT_ID}" ] || bbfatal "Missing AZURE_TENANT_ID in the environment."
    [ -n "${AZURE_FEDERATED_TOKEN_FILE}" ] || \
        bbfatal "Missing AZURE_FEDERATED_TOKEN_FILE. Configure GitHub Actions OIDC."

    fit_certificate="${akv_cert_dir}/fit.der"
    csf_certificate="${akv_cert_dir}/csf.der"
    img_certificate="${akv_cert_dir}/img.der"
    akv_fetch_certificate "${AZURE_FIT_KEY_ID}" "${fit_certificate}"
    akv_fetch_certificate "${AKV_HAB_CSF_KEY_ID}" "${csf_certificate}"
    akv_fetch_certificate "${AKV_HAB_IMG_KEY_ID}" "${img_certificate}"

    {
        printf '{\n  "slots": [\n'
        akv_emit_slot "${AZURE_FIT_KEY_ID}" "${fit_certificate}"
        printf ',\n'
        akv_emit_slot "${AKV_HAB_CSF_KEY_ID}" "${csf_certificate}"
        printf ',\n'
        akv_emit_slot "${AKV_HAB_IMG_KEY_ID}" "${img_certificate}"
        printf '\n  ]\n}\n'
    } > "${akv_config_file}"

    certs=""
    cert_count=0
    for cert_file in ${AKV_HAB_SRK_CERT_FILES}; do
        [ -r "${cert_file}" ] || bbfatal "SRK certificate file is not readable: ${cert_file}"
        if [ -n "${certs}" ]; then
            certs="${certs},${cert_file}"
        else
            certs="${cert_file}"
        fi
        cert_count="$(expr "${cert_count}" + 1)"
    done
    [ "${cert_count}" = "4" ] || \
        bbfatal "AKV_HAB_SRK_CERT_FILES must contain exactly four SRK certificates, got ${cert_count}"

    srktool="${RECIPE_SYSROOT_NATIVE}${bindir}/srktool"
    if [ ! -x "${srktool}" ]; then
        srktool="${TDX_IMX_HAB_CST_DIR}/linux64/bin/srktool"
    fi
    [ -x "${srktool}" ] || bbfatal "srktool not found; cannot generate HAB SRK table/fuse files"

    "${srktool}" \
        --hab_ver 4 \
        --table "${AKV_HAB_SRK_TABLE}" \
        --efuses "${AKV_HAB_SRK_FUSE}" \
        --digest "${TDX_IMX_HAB_CST_DIG_ALGO}" \
        --certs "${certs}" || bbfatal "srktool failed while generating HAB SRK table/fuse files"

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
