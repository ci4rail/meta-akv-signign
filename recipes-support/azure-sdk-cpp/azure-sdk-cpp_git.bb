SUMMARY = "Microsoft Azure SDK for C++ libraries required by azure-keyvault-pkcs11"
HOMEPAGE = "https://github.com/Azure/azure-sdk-for-cpp"
LICENSE = "MIT"
LIC_FILES_CHKSUM = "file://${COMMON_LICENSE_DIR}/MIT;md5=0835ade698e0bcf8506ecda2f7b4f302"

SRC_URI = "\
    git://github.com/Azure/azure-sdk-for-cpp.git;protocol=https;nobranch=1 \
    file://build-required-libraries-only.patch \
"
SRCREV = "35e7740903015383c79d271c0baefedc593fb212"
PV = "1.13.3+git"

S = "${WORKDIR}/git"

inherit cmake pkgconfig

DEPENDS = "\
    curl \
    openssl \
    zlib \
"

FILES:${PN}-dev += "${datadir}/azure-*-cpp"

# Build only the SDK components needed by jepio/azure-keyvault-pkcs11:
# Azure::azure-identity, Azure::azure-security-keyvault-keys and
# Azure::azure-security-keyvault-certificates plus their transitive core deps.
EXTRA_OECMAKE += "\
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
    -DWARNINGS_AS_ERRORS=OFF \
    -DBUILD_TESTING=OFF \
    -DAZ_ALL_LIBRARIES=OFF \
    -DDISABLE_AMQP=ON \
    -DDISABLE_AZURE_CORE_OPENTELEMETRY=ON \
    -DBUILD_TRANSPORT_CURL=ON \
    -DBUILD_TRANSPORT_WINHTTP=OFF \
    -DAZ_BUILD_ONLY='azure-core;azure-identity;azure-security-keyvault-keys;azure-security-keyvault-certificates' \
"

BBCLASSEXTEND = "native"
