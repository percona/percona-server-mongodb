#!/bin/bash
set -euo pipefail

shell_quote_string() {
    echo "$1" | sed -e 's,\([^a-zA-Z0-9/_.=-]\),\\\1,g'
}

usage () {
    cat <<EOF
Usage: $0 [OPTIONS]
    The following options may be given :
        --psmdb_version        PostgreSQL major_version.minor_version
        --repo_type         Repository type
        --help) usage ;;
Example $0 --psmdb_version=7.0.18-11 --repo_type=testing
EOF
        exit 1
}

append_arg_to_args () {
    args="$args "$(shell_quote_string "$1")
}

parse_arguments() {
    pick_args=
    if test "$1" = PICK-ARGS-FROM-ARGV
    then
        pick_args=1
        shift
    fi

    for arg do
        val=$(echo "$arg" | sed -e 's;^--[^=]*=;;')
        case "$arg" in
            --builddir=*) WORKDIR="$val" ;;
            --psmdb_version=*) PSMDB_VERSION="$val" ;;
            --repo_type=*) REPO_TYPE="$val" ;;
            --git_repo=*) GIT_REPO="$val" ;;
            --git_branch=*) GIT_BRANCH="$val" ;;
            --help) usage ;;
            *)
                if test -n "$pick_args"
                then
                    append_arg_to_args "$arg"
                fi
            ;;
        esac
    done
}

CWD=$(pwd)
PSMDB_VERSION=7.0.18-11
REPO_TYPE=testing
ARCH=$(uname -m)

parse_arguments PICK-ARGS-FROM-ARGV "$@"

PSMDB_REPO=$(echo $PSMDB_VERSION | cut -d'.' -f1,2 | tr -d '.')

# Set non-interactive tzdata environment variables to avoid prompts
export DEBIAN_FRONTEND=noninteractive

# Platform detection
if [ -f /etc/os-release ]; then
  . /etc/os-release
  PLATFORM_ID=$(echo "$ID" | tr '[:upper:]' '[:lower:]')
  VERSION_ID=$(echo "$VERSION_ID" | tr -d '"')
else
  echo "Unable to detect OS."
  exit 1
fi

# Function to install dependencies
install_dependencies() {
  case "$PLATFORM_ID" in
    ol|centos|rhel|rocky|almalinux)
      # RHEL/CentOS/OracleLinux (RHEL 8/9)
      RHEL=$(rpm --eval %rhel)
      PLATFORM=${PLATFORM_ID}${RHEL}
      dnf install -y jq
      dnf config-manager --set-enabled ol${RHEL}_codeready_builder || true
      dnf install -y 'dnf-command(config-manager)'
      ;;
    amzn)
      RHEL=$(rpm --eval %amzn)
      PLATFORM=${PLATFORM_ID}${RHEL}
      dnf install -y jq tar
      dnf install -y 'dnf-command(config-manager)'
    ;;
    ubuntu|debian)
      # Install dependencies for Ubuntu/Debian
      PLATFORM=$(echo "$VERSION_CODENAME" | tr '[:upper:]' '[:lower:]')
      apt -y update
      apt install -y curl gnupg jq lsb-release
      ;;
    *)
      echo "Unsupported platform: $PLATFORM_ID"
      exit 1
      ;;
  esac
}

# Install required dependencies
install_dependencies

# Install Percona repo and PostgreSQL
install_percona_mongodb() {
  case "$PLATFORM_ID" in
    ol|rhel|centos|oraclelinux|amzn)
      # Install Percona repo on RHEL/CentOS/OracleLinux/AmazonLinux
      curl -sO https://repo.percona.com/yum/percona-release-latest.noarch.rpm
      dnf install -y percona-release-latest.noarch.rpm
      percona-release enable psmdb-${PSMDB_REPO} ${REPO_TYPE}
      dnf install -y \
	percona-server-mongodb
      ;;
    ubuntu|debian)
      # Install Percona repo on Ubuntu/Debian
      curl -sO https://repo.percona.com/apt/percona-release_latest.generic_all.deb
      dpkg -i percona-release_latest.generic_all.deb
      #apt --fix-broken install -y  # Fix broken dependencies
      apt -y update

      # Explicitly enable the psmdb-${PSMDB_REPO} repository
      percona-release enable telemetry
      percona-release enable psmdb-${PSMDB_REPO} ${REPO_TYPE}
      apt-get -y update
      apt-get install -y \
	percona-server-mongodb
      ;;
    *)
      echo "Unsupported platform: $PLATFORM_ID"
      exit 1
      ;;
  esac
}

# Install Percona repository and PostgreSQL
install_percona_mongodb

# Install Syft (if not already installed)
if ! command -v syft &>/dev/null; then
  curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin
fi

mkdir -p $CWD/psmdb_sbom

# Generate full SBOM using db fallback
echo "Generating full SBOM via db..."
syft dir:/ --output cyclonedx-json > sbom-full-db.json

# Filter PostgreSQL ${PSMDB_VERSION} components and preserve SBOM structure
jq '{
  "$schema": ."$schema",
  "bomFormat": .bomFormat,
  "specVersion": .specVersion,
  "serialNumber": .serialNumber,
  "version": .version,
  "metadata": .metadata,
  "components": [.components[] | select(.name | test("mongodb|percona"; "i"))]
}' sbom-full-db.json > $CWD/psmdb_sbom/sbom-percona-server-${PSMDB_VERSION}-${PLATFORM}-${ARCH}.json

echo "✅ SBOM for Percona PostgreSQL ${PSMDB_VERSION} written to: $CWD/psmdb_sbom/sbom-percona-server-mongodb-${PSMDB_VERSION}-${PLATFORM}-${ARCH}.json"
