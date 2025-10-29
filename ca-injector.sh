#!/usr/bin/env bash
# Excelsior CA Injector Script October 2025
set -euo pipefail
IFS=$'\n\t'

export TERM=xterm-256color
echo "$(tput setaf 45)                     ____ _  _ ____ ____ _    ____ _ ____ ____ "
echo "$(tput setaf 45)                     |___  \/  |    |___ |    [__  | |  | |__/ "
echo "$(tput setaf 45)                     |___ _/\_ |___ |___ |___ ___] | |__| |  \ "
echo "$(tput setaf 7)"
echo "$(tput setaf 7)  **************************************************************************************"
echo "$(tput setaf 7)  *                 NEARLY COMPLETE FreeIPA CA INJECTOR                                 *"
echo "$(tput setaf 7)  **************************************************************************************"
echo "$(tput setaf 7)               Debian FreeIPA CA INJECTOR Script October 2025"
echo

# Defaults & helpers
SCRIPT_NAME="$(basename "$0")"
TMPDIR="$(mktemp -d /tmp/ca-injector.XXXX)"
CERT_FILE="$TMPDIR/excelsior_ca.pem"
INSTALLED_NAME="excelsior_ipaca.crt"
DEST_DIR="/usr/local/share/ca-certificates"
OS="$(. /etc/os-release && echo "$ID:$VERSION_ID" || echo unknown)"
CURL="$(command -v curl || true)"
OPENSSL="$(command -v openssl || true)"
SUDO="$(command -v sudo || true)"


# --- Get target FQDN/IP with safe piping support ---
TARGET="${CA_TARGET:-}"

if [ -z "$TARGET" ]; then
    if [ -t 0 ]; then
        # stdin is a TTY, normal prompt
        read -rp "Enter the FreeIPA CA hostname or IP (e.g. ipaca.excelsior.lan): " TARGET
    else
        # running as curl | bash, read from the real keyboard
        read -rp "Enter the FreeIPA CA hostname or IP (e.g. ipaca.excelsior.lan): " TARGET </dev/tty
    fi
fi

# sanitize & export
TARGET="${TARGET// }"
if [ -z "$TARGET" ]; then
    echo "No CA host provided. Exiting."
    exit 2
fi

export CA_TARGET="$TARGET"
echo "Using FreeIPA CA target: $CA_TARGET"


cleanup() {
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

usage() {
    cat <<EOF
Usage: $SCRIPT_NAME [IP-or-FQDN-or-URL]

Examples:
  Interactive:  sudo bash $SCRIPT_NAME
  Non-interactive: sudo bash $SCRIPT_NAME ipaca.excelsior.lan
  Curl|bash:     curl -fsSL https://ipaca.excelsior.lan/tools/ca-injector.sh | sudo bash -s -- ipaca.excelsior.lan

The script will attempt to download the FreeIPA CA cert from the target and install it into:
  ${DEST_DIR}/$INSTALLED_NAME
EOF
    exit 1
}

if [[ "${1:-}" =~ ^(-h|--help)$ ]]; then
    usage
fi

# Accept argument or prompt
TARGET="${1:-}"
if [ -z "$TARGET" ]; then
    read -rp "Enter the IP or FQDN (or full URL) of the FreeIPA CA server (e.g. ipaca.excelsior.lan): " TARGET
    TARGET="${TARGET## }"
fi
if [ -z "$TARGET" ]; then
    echo "No target provided. Exiting."
    exit 2
fi

# Normalize to no-scheme for printing; but accept URL if provided
if [[ "$TARGET" =~ ^https?:// ]]; then
    TARGET_URL="$TARGET"
    TARGET_HOST="$(echo "$TARGET" | sed -E 's#https?://([^/:]+).*#\1#')"
else
    TARGET_HOST="$TARGET"
    TARGET_URL="https://$TARGET_HOST"
fi

echo
echo "Target: $TARGET_HOST"
echo "Probe URL base: $TARGET_URL"
echo

# quick connectivity + TLS debug using curl
if [ -z "$CURL" ]; then
    echo "curl not found. Install curl and re-run."
    exit 3
fi

echo "== Connectivity & TLS probe (curl -I -sS) =="
set +e
$CURL -I --max-time 10 "$TARGET_URL" 2>&1
CURL_RC=$?
set -e
if [ $CURL_RC -ne 0 ]; then
    echo
    echo "Attempt failed: curl could not reach $TARGET_URL (exit $CURL_RC)."
    echo "We will still attempt to fetch certs from common endpoints and retry with TLS verification disabled if needed."
    echo
fi

# Candidate endpoints commonly used for FreeIPA CA certs
CANDIDATES=(
    "$TARGET_URL/ipa/config/ca.crt"
    "$TARGET_URL/ipa/ca.crt"
    "$TARGET_URL/ipa/config/ca.pem"
    "$TARGET_URL/ca.crt"
    "$TARGET_URL/ca.pem"
    "$TARGET_URL/certs/ca-bundle.crt"
    "$TARGET_URL/certs/ca.pem"
    "$TARGET_URL/ipa/config/caBundle.pem"
)

echo "Trying to download certificate from common FreeIPA endpoints..."
FOUND=0
for ep in "${CANDIDATES[@]}"; do
    echo -n " -> Trying $ep ... "
    set +e
    # First, try with verification
    if $CURL -fsS --max-time 15 -o "$CERT_FILE" "$ep"; then
        echo "OK (TLS verified)"
        FOUND=1
        TLS_INSECURE=0
        break
    fi
    # If that fails, try with -k (insecure) and note that fact
    if $CURL -fsS --max-time 15 -o "$CERT_FILE" -k "$ep"; then
        echo "OK (fetched with -k; TLS not verified)"
        FOUND=1
        TLS_INSECURE=1
        break
    fi
    set -e
    echo "no"
done

if [ "$FOUND" -ne 1 ]; then
    echo
    echo "Could not download certificate from the usual endpoints. As a last attempt, try the host root:"
    set +e
    if $CURL -fsS --max-time 15 -o "$CERT_FILE" "$TARGET_URL/"; then
        # may have HTML; try to extract PEM-looking block
        if grep -q "BEGIN CERTIFICATE" "$CERT_FILE"; then
            echo "Found PEM block at root path."
            FOUND=1
            TLS_INSECURE=0
        else
            echo "Root fetched but no PEM block found."
        fi
    else
        echo "Root fetch failed."
    fi
    set -e
fi

if [ "$FOUND" -ne 1 ]; then
    echo
    echo "ERROR: Unable to retrieve a certificate from $TARGET_URL using the tested endpoints."
    echo "Possible causes:"
    echo " - target is not reachable"
    echo " - FreeIPA CA endpoint path is different"
    echo " - firewall blocks access"
    echo " - TLS requires client auth"
    echo
    echo "You can run this script with a direct URL to a PEM file, e.g. https://ipaca.excelsior.lan/ipa/config/ca.crt"
    exit 4
fi

# Ensure file contains a PEM certificate
if ! grep -q "BEGIN CERTIFICATE" "$CERT_FILE"; then
    echo "Downloaded file does not appear to contain a PEM certificate. Showing head of file for inspection:"
    sed -n '1,60p' "$CERT_FILE"
    exit 5
fi

echo
echo "== Certificate raw head (first 40 lines) =="
sed -n '1,40p' "$CERT_FILE" || true
echo

# Validate with OpenSSL if available
if [ -n "$OPENSSL" ]; then
    echo "== OpenSSL validation =="
    set +e
    $OPENSSL x509 -in "$CERT_FILE" -noout -subject -issuer -dates -fingerprint -sha256 2>/dev/null || true
    echo
    echo "== SHA256 fingerprint (hex, colon separated) =="
    $OPENSSL x509 -in "$CERT_FILE" -noout -fingerprint -sha256 | sed 's/^SHA256 Fingerprint=//'
    set -e
else
    echo "openssl not found; skipping certificate parsing. Install openssl for more inspection."
fi

# Install certificate
echo
echo "== Installing certificate to system trust store =="
if [ "$(id -u)" -ne 0 ]; then
    if [ -z "$SUDO" ]; then
        echo "This operation requires root privileges. Rerun with sudo or as root."
        exit 6
    fi
    echo "Using sudo to copy certificate into $DEST_DIR"
    $SUDO mkdir -p "$DEST_DIR"
    $SUDO cp "$CERT_FILE" "$DEST_DIR/$INSTALLED_NAME"
    $SUDO chmod 644 "$DEST_DIR/$INSTALLED_NAME"
    # Run update-ca-certificates on Debian/Ubuntu; alternative handled below
    if command -v update-ca-certificates >/dev/null 2>&1; then
        echo "Running update-ca-certificates..."
        $SUDO update-ca-certificates
    elif command -v trust >/dev/null 2>&1; then
        # For systems using p11-kit / 'trust' (less common for Ubuntu/Debian)
        echo "Using 'trust' to add certificate to system store..."
        $SUDO trust anchor --store "$DEST_DIR/$INSTALLED_NAME"
    else
        echo "No known system command found to update CA trust. Certificate copied to $DEST_DIR/$INSTALLED_NAME"
        echo "You will need to manually add it to the trust store for your distribution."
    fi
else
    mkdir -p "$DEST_DIR"
    cp "$CERT_FILE" "$DEST_DIR/$INSTALLED_NAME"
    chmod 644 "$DEST_DIR/$INSTALLED_NAME"
    if command -v update-ca-certificates >/dev/null 2>&1; then
        echo "Running update-ca-certificates..."
        update-ca-certificates
    elif command -v trust >/dev/null 2>&1; then
        echo "Using 'trust' to add certificate to system store..."
        trust anchor --store "$DEST_DIR/$INSTALLED_NAME"
    else
        echo "No known system command found to update CA trust. Certificate copied to $DEST_DIR/$INSTALLED_NAME"
    fi
fi

echo
echo "== Verification: list the installed cert file and show fingerprint again =="
if [ -n "$SUDO" ] && [ "$(id -u)" -ne 0 ]; then
    $SUDO ls -l "$DEST_DIR/$INSTALLED_NAME" || true
    if [ -n "$OPENSSL" ]; then
        $SUDO $OPENSSL x509 -in "$DEST_DIR/$INSTALLED_NAME" -noout -subject -issuer -dates -fingerprint -sha256 || true
    fi
else
    ls -l "$DEST_DIR/$INSTALLED_NAME" || true
    if [ -n "$OPENSSL" ]; then
        $OPENSSL x509 -in "$DEST_DIR/$INSTALLED_NAME" -noout -subject -issuer -dates -fingerprint -sha256 || true
    fi
fi

echo
echo "== Final notes =="
echo " - Certificate installed to: $DEST_DIR/$INSTALLED_NAME"
echo " - If you run services that cache CA stores (Java, NSS, Docker), you may need to restart them or update their specific stores."
echo " - If you fetched the cert with TLS verification disabled, you should verify the fingerprint out-of-band before trusting."
if [ "${TLS_INSECURE:-0}" -eq 1 ]; then
    echo
    echo "!!! WARNING: certificate was fetched with TLS verification disabled (-k). Verify the SHA256 fingerprint above against an out-of-band source before trusting."
fi

echo
echo "Done. Cleaned temp files."
exit 0
