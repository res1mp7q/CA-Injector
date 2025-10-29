#!/usr/bin/env bash
# Excelsior CA Injector Script October 2025
# Portable installer to fetch FreeIPA CA cert and add to Debian/Ubuntu trust store.
set -euo pipefail
IFS=$'\n\t'

export TERM=xterm-256color
echo "$(tput setaf 45)                     ____ _  _ ____ ____ _    ____ _ ____ ____ "
echo "$(tput setaf 45)                     |___  \/  |    |___ |    [__  | |  | |__/ "
echo "$(tput setaf 45)                     |___ _/\_ |___ |___ |___ ___] | |__| |  \ "
echo "$(tput setaf 7)"
echo "$(tput setaf 7)  **************************************************************************************"
echo "$(tput setaf 7)  *                             FreeIPA CA INJECTOR                                    *"
echo "$(tput setaf 7)  **************************************************************************************"
echo "$(tput setaf 7)                  Debian FreeIPA CA INJECTOR Script October 2025"
echo

# temp work dir
TMPDIR="$(mktemp -d /tmp/ca-injector.XXXX)"
CERT_FILE="$TMPDIR/ca.pem"
INSTALLED_NAME="ipaca.crt"
DEST_DIR="/usr/local/share/ca-certificates"
CURL="$(command -v curl || true)"
OPENSSL="$(command -v openssl || true)"
SUDO="$(command -v sudo || true)"

cleanup() { rm -rf "$TMPDIR"; }
trap cleanup EXIT

usage() {
  cat <<EOF
Usage: $0 [IP-or-FQDN-or-URL]

Examples:
  Interactive:  sudo bash $0
  Non-interactive: sudo bash $0 ipaca.foo.lan
  Curl|bash:     curl -fsSL https://inject.ex777.us | sudo bash -s -- ipaca.foo.lan
EOF
  exit 1
}

# ---------- TARGET PROMPT (robust for curl|bash) ----------
# Priority: CLI arg > CA_TARGET env > interactive prompt (read from TTY if piped)
TARGET="${1:-${CA_TARGET:-}}"

if [ -z "$TARGET" ]; then
  if [ -t 0 ]; then
    # stdin is TTY
    read -rp "Enter the FreeIPA CA hostname or IP (e.g. ipaca.foo.lan): " TARGET
  else
    # stdin is a pipe (curl | bash) -> read from the real terminal
    if [ -e /dev/tty ]; then
      read -rp "Enter the FreeIPA CA hostname or IP (e.g. ipaca.foo.lan): " TARGET </dev/tty
    else
      echo "No interactive terminal available. Provide target as argument or CA_TARGET env var."
      usage
    fi
  fi
fi

# sanitize and export
TARGET="${TARGET## }"
TARGET="${TARGET%% }"
if [ -z "$TARGET" ]; then
  echo "No CA host provided. Exiting."
  exit 2
fi
export CA_TARGET="$TARGET"
echo "Using FreeIPA CA target: $CA_TARGET"
echo

# Normalize URL
if [[ "$CA_TARGET" =~ ^https?:// ]]; then
  TARGET_URL="$CA_TARGET"
  TARGET_HOST="$(echo "$CA_TARGET" | sed -E 's#https?://([^/:]+).*#\1#')"
else
  TARGET_HOST="$CA_TARGET"
  TARGET_URL="https://$TARGET_HOST"
fi

# ---------- quick connectivity probe ----------
if [ -z "$CURL" ]; then
  echo "curl not found. Please install curl and retry."
  exit 3
fi

echo "== Connectivity probe =="
set +e
$CURL -I --max-time 10 "$TARGET_URL" 2>&1 || true
set -e
echo

# ---------- candidate endpoints ----------
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
TLS_INSECURE=0

for ep in "${CANDIDATES[@]}"; do
  echo -n " -> Trying $ep ... "
  set +e
  if $CURL -fsS --max-time 15 -o "$CERT_FILE" "$ep"; then
    echo "OK (TLS verified)"
    FOUND=1; TLS_INSECURE=0; set -e; break
  fi
  if $CURL -fsS --max-time 15 -o "$CERT_FILE" -k "$ep"; then
    echo "OK (fetched with -k; TLS not verified)"
    FOUND=1; TLS_INSECURE=1; set -e; break
  fi
  set -e
  echo "no"
done

if [ "$FOUND" -ne 1 ]; then
  echo "Last attempt: fetch root and extract PEM if present..."
  set +e
  if $CURL -fsS --max-time 15 -o "$CERT_FILE" "$TARGET_URL/"; then
    if grep -q "BEGIN CERTIFICATE" "$CERT_FILE"; then
      echo "Found PEM block at root path."
      FOUND=1; TLS_INSECURE=0
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
  echo "ERROR: Unable to retrieve a certificate from $TARGET_URL."
  echo "Check reachability, endpoint path, firewall, or TLS client requirements."
  exit 4
fi

# validate file looks like a PEM cert
if ! grep -q "BEGIN CERTIFICATE" "$CERT_FILE"; then
  echo "Downloaded file does not contain a PEM certificate. Preview:"
  sed -n '1,80p' "$CERT_FILE"
  exit 5
fi

echo
echo "== Certificate (head) =="
sed -n '1,40p' "$CERT_FILE" || true
echo

if [ -n "$OPENSSL" ]; then
  echo "== OpenSSL details =="
  $OPENSSL x509 -in "$CERT_FILE" -noout -subject -issuer -dates -fingerprint -sha256 || true
  echo
  echo "SHA256 Fingerprint:"
  $OPENSSL x509 -in "$CERT_FILE" -noout -fingerprint -sha256 | sed 's/^SHA256 Fingerprint=//'
else
  echo "openssl not found; install openssl for extra checks."
fi

# ---------- INSTALL ----------
echo
echo "== Installing certificate to system trust store =="
if [ "$(id -u)" -ne 0 ]; then
  if [ -n "$SUDO" ]; then
    $SUDO mkdir -p "$DEST_DIR"
    $SUDO cp "$CERT_FILE" "$DEST_DIR/$INSTALLED_NAME"
    $SUDO chmod 644 "$DEST_DIR/$INSTALLED_NAME"
    if command -v update-ca-certificates >/dev/null 2>&1; then
      echo "Running update-ca-certificates..."
      $SUDO update-ca-certificates
    elif command -v trust >/dev/null 2>&1; then
      echo "Using 'trust' to add certificate..."
      $SUDO trust anchor --store "$DEST_DIR/$INSTALLED_NAME"
    else
      echo "Certificate copied to $DEST_DIR/$INSTALLED_NAME. Manually update trust store if needed."
    fi
  else
    echo "This operation requires root privileges. Rerun with sudo or as root."
    exit 6
  fi
else
  mkdir -p "$DEST_DIR"
  cp "$CERT_FILE" "$DEST_DIR/$INSTALLED_NAME"
  chmod 644 "$DEST_DIR/$INSTALLED_NAME"
  if command -v update-ca-certificates >/dev/null 2>&1; then
    echo "Running update-ca-certificates..."
    update-ca-certificates
  elif command -v trust >/dev/null 2>&1; then
    trust anchor --store "$DEST_DIR/$INSTALLED_NAME"
  else
    echo "Certificate copied to $DEST_DIR/$INSTALLED_NAME. Manually update trust store if needed."
  fi
fi

echo
echo "== Installed cert file =="
if [ -n "$SUDO" ] && [ "$(id -u)" -ne 0 ]; then
  $SUDO ls -l "$DEST_DIR/$INSTALLED_NAME" || true
  if [ -n "$OPENSSL" ]; then $SUDO $OPENSSL x509 -in "$DEST_DIR/$INSTALLED_NAME" -noout -subject -issuer -dates -fingerprint -sha256 || true; fi
else
  ls -l "$DEST_DIR/$INSTALLED_NAME" || true
  if [ -n "$OPENSSL" ]; then $OPENSSL x509 -in "$DEST_DIR/$INSTALLED_NAME" -noout -subject -issuer -dates -fingerprint -sha256 || true; fi
fi

echo
echo "Final notes:"
echo " - Certificate installed to: $DEST_DIR/$INSTALLED_NAME"
echo " - Restart services that cache CA stores (Java, NSS, Docker) if required."
if [ "${TLS_INSECURE:-0}" -eq 1 ]; then
  echo "!!! WARNING: certificate fetched with TLS verification disabled (-k). Verify fingerprint out-of-band."
fi

echo
echo "Done."
exit 0
