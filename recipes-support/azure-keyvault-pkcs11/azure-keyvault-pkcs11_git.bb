SUMMARY = "PKCS#11 provider backed by Azure Key Vault"
HOMEPAGE = "https://github.com/jepio/azure-keyvault-pkcs11"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "git://github.com/jepio/azure-keyvault-pkcs11.git;protocol=https;branch=main"
SRCREV = "c72d89bf0b17f8c21a93870efaaabb93c0dc9c63"
PV = "0.1+git"

S = "${WORKDIR}/git"

inherit cmake pkgconfig

DEPENDS = "\
    azure-sdk-cpp \
    json-c \
    openssl \
    p11-kit \
"

EXTRA_OECMAKE += "\
    -DCMAKE_BUILD_TYPE=Release \
"

FILES:${PN} += "${libdir}/pkcs11/azure-keyvault-pkcs11.so"

BBCLASSEXTEND = "native"
