#!/usr/bin/env bash
set -e

#
# Helper script for local development. Automatically builds and registers the
# plugin. Requires `vault` is installed and available on $PATH.
#

# Get the right dir
DIR="$(cd "$(dirname "$(readlink "$0")")" && pwd)"

echo "==> Starting dev"

echo "--> Scratch dir"
echo "    Creating"
SCRATCH="$DIR/tmp"
mkdir -p "$SCRATCH/plugins"

echo "--> Vault server"
echo "    Writing config"
tee "$SCRATCH/vault.hcl" > /dev/null <<EOF
plugin_directory = "$SCRATCH/plugins"
EOF

echo "    Envvars"
export VAULT_DEV_ROOT_TOKEN_ID="root"
export VAULT_ADDR="http://127.0.0.1:8200"

echo "    Starting"
vault server \
  -dev \
  -log-level="debug" \
  -config="$SCRATCH/vault.hcl" \
  &
sleep 2
VAULT_PID=$!

function cleanup {
  echo ""
  echo "==> Cleaning up"
  kill -INT "$VAULT_PID"
  rm -rf "$SCRATCH"
}
trap cleanup EXIT

echo "    Authing"
vault login root &>/dev/null

echo "--> Building"
go build -o "$SCRATCH/plugins/azure-vault-backend"
SHASUM=$(shasum -a 256 "$SCRATCH/plugins/azure-vault-backend" | cut -d " " -f1)

echo "    Registering plugin"
vault write sys/plugins/catalog/secret/azure-token-gen \
  sha_256="$SHASUM" \
  command="azure-vault-backend"

echo "    Mouting plugin"
vault secrets enable -path=azure/1 -plugin-name=azure-token-gen plugin

echo "==> Ready!"
wait $!
