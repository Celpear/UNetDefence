#!/usr/bin/env bash
# Setup UNetDefence: install (Python, Zeek, Suricata), detect paths, write .env, migrations, Ollama check.
# Usage: ./scripts/setup.sh [--no-install] [--skip-ids] [--zeek-dir DIR] [--suricata-path PATH]
set -e
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

NO_INSTALL=""
SKIP_IDS=""
ZEEK_DIR=""
SURICATA_PATH=""
while [ $# -gt 0 ]; do
  case "$1" in
    --no-install) NO_INSTALL=1 ;;
    --skip-ids)   SKIP_IDS=1 ;;
    --zeek-dir)    ZEEK_DIR="$2"; shift ;;
    --suricata-path) SURICATA_PATH="$2"; shift ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
  shift
done

echo "UNetDefence setup (repo: $REPO_ROOT)"
echo ""

# --- 1. Install (venv + pip install -e .) ---
if [ -z "$NO_INSTALL" ]; then
  if [ ! -d ".venv" ]; then
    echo "Creating .venv..."
    python3 -m venv .venv
  fi
  echo "Installing package (editable)..."
  # shellcheck source=/dev/null
  source .venv/bin/activate
  pip install -e . -q
  echo "  Done."
else
  if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
  fi
fi
echo ""

# --- 2. Install Zeek and Suricata (if missing) ---
if [ -n "$SKIP_IDS" ]; then
  echo "Skipping Zeek/Suricata install (--skip-ids)."
else
echo "Checking Zeek / Suricata..."
INSTALLED_IDS=""
# Linux: ensure Zeek bin in PATH (e.g. /opt/zeek/bin after apt install)
[ -d /opt/zeek/bin ] && export PATH="$PATH:/opt/zeek/bin"
if command -v zeek &>/dev/null; then
  echo "  Zeek already installed ($(zeek -v 2>/dev/null | head -1 || echo 'zeek')"
else
  if [ "$(uname -s)" = "Darwin" ] && command -v brew &>/dev/null; then
    echo "  Installing Zeek via Homebrew..."
    brew install zeek && INSTALLED_IDS="${INSTALLED_IDS} zeek" || echo "  Zeek install failed (run manually: brew install zeek)"
  elif [ -f /etc/os-release ] && command -v apt-get &>/dev/null; then
    # Debian/Ubuntu: add Zeek repo for Ubuntu (Zeek not in default repos)
    . /etc/os-release
    if [ "${ID}" = "ubuntu" ] && [ -n "${VERSION_ID}" ]; then
      ZEEK_REPO="xUbuntu_${VERSION_ID}"
      echo "  Adding Zeek repo for Ubuntu ${VERSION_ID}..."
      curl -fsSL "https://download.opensuse.org/repositories/security:zeek/${ZEEK_REPO}/Release.key" | gpg --dearmor 2>/dev/null | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg >/dev/null
      echo "deb http://download.opensuse.org/repositories/security:/zeek/${ZEEK_REPO}/ /" | sudo tee /etc/apt/sources.list.d/security:zeek.list >/dev/null
    fi
    echo "  Installing Zeek via apt..."
    sudo apt-get update -qq && sudo apt-get install -y zeek && INSTALLED_IDS="${INSTALLED_IDS} zeek" && export PATH="$PATH:/opt/zeek/bin" || echo "  Zeek install failed (Ubuntu: repo added; other: see https://docs.zeek.org/install)"
  elif [ -f /etc/redhat-release ] && command -v dnf &>/dev/null; then
    echo "  Installing Zeek via dnf..."
    sudo dnf install -y zeek && INSTALLED_IDS="${INSTALLED_IDS} zeek" && [ -d /opt/zeek/bin ] && export PATH="$PATH:/opt/zeek/bin" || echo "  Zeek install failed (see https://docs.zeek.org/install)"
  else
    echo "  Zeek not found. Install manually: macOS: brew install zeek  |  Linux: see https://docs.zeek.org/install/"
  fi
fi
if command -v suricata &>/dev/null; then
  echo "  Suricata already installed ($(suricata -V 2>/dev/null | head -1 || echo 'suricata')"
else
  if [ "$(uname -s)" = "Darwin" ] && command -v brew &>/dev/null; then
    echo "  Installing Suricata via Homebrew..."
    brew install suricata && INSTALLED_IDS="${INSTALLED_IDS} suricata" || echo "  Suricata install failed (run manually: brew install suricata)"
  elif [ -f /etc/debian_version ] && command -v apt-get &>/dev/null; then
    echo "  Installing Suricata via apt..."
    sudo apt-get update -qq && sudo apt-get install -y suricata && INSTALLED_IDS="${INSTALLED_IDS} suricata" || echo "  Suricata install failed"
  elif [ -f /etc/redhat-release ] && command -v dnf &>/dev/null; then
    echo "  Installing Suricata via dnf..."
    sudo dnf install -y suricata && INSTALLED_IDS="${INSTALLED_IDS} suricata" || echo "  Suricata install failed"
  else
    echo "  Suricata not found. Install manually: macOS: brew install suricata  |  Linux: sudo apt-get install suricata"
  fi
fi
[ -n "$INSTALLED_IDS" ] && echo "  Installed:$INSTALLED_IDS"
fi
echo ""

# --- 3. Detect Zeek / Suricata paths if not given ---
if [ -z "$ZEEK_DIR" ]; then
  for d in /var/log/zeek /var/log/bro /usr/local/var/log/zeek /opt/zeek/logs "$HOME/zeek/logs" "$HOME/logs/zeek"; do
    if [ -n "$d" ] && [ -f "${d}/conn.log" ]; then
      ZEEK_DIR="$d"
      echo "Detected Zeek log dir: $ZEEK_DIR"
      break
    fi
  done
  # Default paths after install (logs appear after first run of Zeek)
  if [ -z "$ZEEK_DIR" ] && command -v zeek &>/dev/null; then
    if [ "$(uname -s)" = "Darwin" ]; then
      if [ -d "/opt/homebrew/var/log/zeek" ]; then ZEEK_DIR="/opt/homebrew/var/log/zeek"
      elif [ -d "/usr/local/var/log/zeek" ]; then ZEEK_DIR="/usr/local/var/log/zeek"
      else
        ZEEK_DIR="/opt/homebrew/var/log/zeek"; [ ! -d "$ZEEK_DIR" ] && ZEEK_DIR="/usr/local/var/log/zeek"
        echo "Zeek installed; using default log dir $ZEEK_DIR (create with: sudo mkdir -p $ZEEK_DIR && sudo chown \$USER $ZEEK_DIR)"
      fi
    else
      ZEEK_DIR="/var/log/zeek"
      echo "Zeek installed; using default log dir $ZEEK_DIR"
    fi
    [ -n "$ZEEK_DIR" ] && echo "Zeek log dir (default): $ZEEK_DIR"
  fi
  [ -z "$ZEEK_DIR" ] && echo "Zeek: no log dir found (set later with --zeek-dir or in .env)"
fi

if [ -z "$SURICATA_PATH" ]; then
  for f in /var/log/suricata/eve.json /usr/local/var/log/suricata/eve.json /opt/homebrew/var/log/suricata/eve.json /opt/suricata/var/log/eve.json "$HOME/suricata/logs/eve.json"; do
    if [ -n "$f" ] && [ -f "$f" ]; then
      SURICATA_PATH="$f"
      echo "Detected Suricata eve.json: $SURICATA_PATH"
      break
    fi
  done
  # Default path after install (eve.json created when Suricata runs)
  if [ -z "$SURICATA_PATH" ] && command -v suricata &>/dev/null; then
    if [ "$(uname -s)" = "Darwin" ]; then
      [ -d /opt/homebrew ] && SURICATA_PATH="/opt/homebrew/var/log/suricata/eve.json" || SURICATA_PATH="/usr/local/var/log/suricata/eve.json"
    else
      SURICATA_PATH="/var/log/suricata/eve.json"
    fi
    echo "Suricata installed; using default eve.json path: $SURICATA_PATH"
  fi
  [ -z "$SURICATA_PATH" ] && echo "Suricata: no eve.json found (set later with --suricata-path or in .env)"
fi
echo ""

# --- 3. Update .env (keep existing vars, set ingest) ---
ENV_FILE="$REPO_ROOT/.env"
touch "$ENV_FILE"
TMP="$(mktemp)"
# Keep all lines except ingest vars
grep -v '^UNETDEFENCE_INGEST_ZEEK_LOG_DIR=' "$ENV_FILE" 2>/dev/null | grep -v '^UNETDEFENCE_INGEST_SURICATA_EVE_PATH=' > "$TMP" || true
# Add newline before new vars if file had content
[ -s "$TMP" ] && echo "" >> "$TMP"
if [ -n "$ZEEK_DIR" ]; then
  echo "UNETDEFENCE_INGEST_ZEEK_LOG_DIR=$ZEEK_DIR" >> "$TMP"
  echo "  Set UNETDEFENCE_INGEST_ZEEK_LOG_DIR=$ZEEK_DIR"
fi
if [ -n "$SURICATA_PATH" ]; then
  echo "UNETDEFENCE_INGEST_SURICATA_EVE_PATH=$SURICATA_PATH" >> "$TMP"
  echo "  Set UNETDEFENCE_INGEST_SURICATA_EVE_PATH=$SURICATA_PATH"
fi
mv "$TMP" "$ENV_FILE"
echo ""

# --- 4. Migrate DB ---
echo "Running DB migrations..."
python -m unetdefence.storage.migrate
echo ""

# --- 5. Ollama: check/pull configured LLM (and optional embedding) model ---
echo "Checking Ollama models (from .env / config)..."
if unetdefence-ensure-ollama; then
  echo "  Ollama models OK."
else
  echo "  Ollama not reachable or pull failed. Start Ollama and run: unetdefence-ensure-ollama"
fi
echo ""

echo "Setup done. Next:"
echo "  unetdefence-api          # start API"
echo "  unetdefence-ingest       # start ingest (if Zeek/Suricata paths are set)"
echo "  unetdefence-ensure-ollama   # (if Ollama was not running during setup)"
echo "  GET /health/stats       # check ingest_configured and counts"
