#!/bin/bash

# This flags makes the script exit if any command has a non-zero exit status, or 
# if tries to use a non defined variable
set -e -o nounset

# Default values
chain_id=""
wasm_file=""
wasm_args_file=""
policy_file=""
schema_file=""
entrypoint=""
policy_metadata_file=""
policy_data_metadata_file=""
out=""

# Parse command line arguments
# wasm_file, wasm_args_file, policy_file, schema_file, entrypoint, policy_metadata_file, policy_data_metadata_file, out
while getopts "c:w:a:p:s:e:m:d:o:h" opt; do
    case $opt in
        c)
            chain_id="$OPTARG"
            ;;
        w)
            wasm_file="$OPTARG"
            ;;
        a)
            wasm_args_file="$OPTARG"
            ;;
        p)
            policy_file="$OPTARG"
            ;;
        s)
            schema_file="$OPTARG"
            ;;
        e)
            entrypoint="$OPTARG"
            ;;
        m)
            policy_metadata_file="$OPTARG"
            ;;
        d)
            policy_data_metadata_file="$OPTARG"
            ;;
        o)
            out="$OPTARG"
            ;;
        h)
            echo "Usage: $0 --chain-id <chain_id> --wasm-file <wasm_file> --wasm-args-file <wasm_args_file> \
            --policy-file <policy_file> --schema-file <schema_file> --entrypoint <entrypoint> \
            --policy-metadata-file <policy_metadata_file> --policy-data-metadata-file <policy_data_metadata_file> \
            --out <out>"
            exit 0
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
    esac
done

if [ -z "$chain_id" ] || [ -z "$wasm_file" ] || [ -z "$policy_file" ] || [ -z "$schema_file" ] || \
[ -z "$entrypoint" ] || [ -z "$policy_metadata_file" ] || [ -z "$policy_data_metadata_file" ]; then
    echo "Error: Missing required parameters"
    exit 1
fi

echo "Chain ID: $chain_id"
echo "WASM File: $wasm_file"
echo "WASM Args File: $wasm_args_file"
echo "Policy File: $policy_file"
echo "Schema File: $schema_file"
echo "Entrypoint: $entrypoint"
echo "Policy Metadata File: $policy_metadata_file"
echo "Policy Data Metadata File: $policy_data_metadata_file"
echo "Output Directory: $out"

# Source the .env file
if [[ "$chain_id" = "31337" ]]; then
    ENV_FILE_PATH="contracts/.env.anvil"
else
    ENV_FILE_PATH="contracts/.env"
fi

WASM_GATEWAY_LINK=""
WASM_ARGS_GATEWAY_LINK=""
POLICY_GATEWAY_LINK=""
SCHEMA_GATEWAY_LINK=""
POLICY_METADATA_GATEWAY_LINK=""
POLICY_DATA_METADATA_GATEWAY_LINK=""

echo "==========================================================="
echo "============== Upload Policy Metadata component ==========="
echo "==========================================================="
echo "$policy_metadata_file" > /tmp/policy_metadata_file_path
POLICY_METADATA_FILE=$(cat /tmp/policy_metadata_file_path); \
~/.local/share/pinata/pinata upload "$POLICY_METADATA_FILE" --name "newton-policy-metadata-$(date +%Y%m%d-%H%M%S)" | tee /tmp/pinata_upload.log
IPFS_HASH=$(grep -o 'Qm[A-Za-z0-9]\{44\}\|baf[A-Za-z0-9]\{55,\}' /tmp/pinata_upload.log | head -1); \
if [ -n "$IPFS_HASH" ]; then \
    echo "IPFS Hash: $IPFS_HASH"; \
    echo "Getting gateway link..."; \
    POLICY_METADATA_GATEWAY_LINK=$(~/.local/share/pinata/pinata gateways link "$IPFS_HASH" 2>/dev/null || echo "https://gateway.pinata.cloud/ipfs/$IPFS_HASH"); \
    echo "Direct IPFS Link: $POLICY_METADATA_GATEWAY_LINK"; \
    echo "Public IPFS Link: https://ipfs.io/ipfs/$IPFS_HASH"; \
else \
    echo "Warning: Could not extract IPFS hash from upload output"; \
    cat /tmp/pinata_upload.log; \
fi
rm -f /tmp/pinata_upload.log /tmp/policy_metadata_file_path

echo "================================================================"
echo "============== Upload Policy Data Metadata component ==========="
echo "================================================================"
echo "$policy_data_metadata_file" > /tmp/policy_data_metadata_file_path
POLICY_DATA_METADATA_FILE=$(cat /tmp/policy_data_metadata_file_path); \
~/.local/share/pinata/pinata upload "$POLICY_DATA_METADATA_FILE" --name "newton-policy-data-metadata-$(date +%Y%m%d-%H%M%S)" | tee /tmp/pinata_upload.log
IPFS_HASH=$(grep -o 'Qm[A-Za-z0-9]\{44\}\|baf[A-Za-z0-9]\{55,\}' /tmp/pinata_upload.log | head -1); \
if [ -n "$IPFS_HASH" ]; then \
    echo "IPFS Hash: $IPFS_HASH"; \
    echo "Getting gateway link..."; \
    POLICY_DATA_METADATA_GATEWAY_LINK=$(~/.local/share/pinata/pinata gateways link "$IPFS_HASH" 2>/dev/null || echo "https://gateway.pinata.cloud/ipfs/$IPFS_HASH"); \
    echo "Direct IPFS Link: $POLICY_DATA_METADATA_GATEWAY_LINK"; \
    echo "Public IPFS Link: https://ipfs.io/ipfs/$IPFS_HASH"; \
else \
    echo "Warning: Could not extract IPFS hash from upload output"; \
    cat /tmp/pinata_upload.log; \
fi
rm -f /tmp/pinata_upload.log /tmp/policy_data_metadata_file_path

echo "================================================"
echo "============== Upload WASM component ==========="
echo "================================================"
echo "$wasm_file" > /tmp/wasm_file_path
WASM_FILE=$(cat /tmp/wasm_file_path); \
~/.local/share/pinata/pinata upload "$WASM_FILE" --name "newton-policy-wasm-$(date +%Y%m%d-%H%M%S)" | tee /tmp/pinata_upload.log
IPFS_HASH=$(grep -o 'Qm[A-Za-z0-9]\{44\}\|baf[A-Za-z0-9]\{55,\}' /tmp/pinata_upload.log | head -1); \
if [ -n "$IPFS_HASH" ]; then \
    echo "IPFS Hash: $IPFS_HASH"; \
    echo "Getting gateway link..."; \
    WASM_GATEWAY_LINK=$(~/.local/share/pinata/pinata gateways link "$IPFS_HASH" 2>/dev/null || echo "https://gateway.pinata.cloud/ipfs/$IPFS_HASH"); \
    echo "Direct IPFS Link: $WASM_GATEWAY_LINK"; \
    echo "Public IPFS Link: https://ipfs.io/ipfs/$IPFS_HASH"; \
else \
    echo "Warning: Could not extract IPFS hash from upload output"; \
    cat /tmp/pinata_upload.log; \
fi
rm -f /tmp/pinata_upload.log /tmp/wasm_file_path

if [ -n "$wasm_args_file" ]; then
    echo "======================================================="
    echo "============== Upload WASM args component ============="
    echo "======================================================="
    echo "$wasm_args_file" > /tmp/wasm_args_file_path
    WASM_ARGS_FILE=$(cat /tmp/wasm_args_file_path); \
    ~/.local/share/pinata/pinata upload "$WASM_ARGS_FILE" --name "newton-policy-wasm-args-$(date +%Y%m%d-%H%M%S)" | tee /tmp/pinata_upload.log
    IPFS_HASH=$(grep -o 'Qm[A-Za-z0-9]\{44\}\|baf[A-Za-z0-9]\{55,\}' /tmp/pinata_upload.log | head -1); \
    if [ -n "$IPFS_HASH" ]; then \
        echo "IPFS Hash: $IPFS_HASH"; \
        echo "Getting gateway link..."; \
        WASM_ARGS_GATEWAY_LINK=$(~/.local/share/pinata/pinata gateways link "$IPFS_HASH" 2>/dev/null || echo "https://gateway.pinata.cloud/ipfs/$IPFS_HASH"); \
        echo "Direct IPFS Link: $WASM_ARGS_GATEWAY_LINK"; \
        echo "Public IPFS Link: https://ipfs.io/ipfs/$IPFS_HASH"; \
    else \
        echo "Warning: Could not extract IPFS hash from upload output"; \
        cat /tmp/pinata_upload.log; \
    fi
    rm -f /tmp/pinata_upload.log /tmp/wasm_args_file_path
else
    echo "======================================================="
    echo "============== Skipping WASM args component ==========="
    echo "======================================================="
    echo "No WASM args file provided, skipping upload..."
fi

echo "================================================"
echo "============== Upload policy.rego =============="
echo "================================================"
~/.local/share/pinata/pinata upload "$policy_file" --name "newton-policy-$(date +%Y%m%d-%H%M%S)" | tee /tmp/pinata_upload.log
IPFS_HASH=$(grep -o 'Qm[A-Za-z0-9]\{44\}\|baf[A-Za-z0-9]\{55,\}' /tmp/pinata_upload.log | head -1); \
if [ -n "$IPFS_HASH" ]; then \
    echo "IPFS Hash: $IPFS_HASH"; \
    echo "Getting gateway link..."; \
    POLICY_GATEWAY_LINK=$(~/.local/share/pinata/pinata gateways link "$IPFS_HASH" 2>/dev/null || echo "https://gateway.pinata.cloud/ipfs/$IPFS_HASH"); \
    echo "Direct IPFS Link: $POLICY_GATEWAY_LINK"; \
    echo "Public IPFS Link: https://ipfs.io/ipfs/$IPFS_HASH"; \
else \
    echo "Warning: Could not extract IPFS hash from upload output"; \
    cat /tmp/pinata_upload.log; \
fi
rm -f /tmp/pinata_upload.log

echo "================================================"
echo "========== Upload params_schema.json ==========="
echo "================================================"
~/.local/share/pinata/pinata upload "$schema_file" --name "newton-policy-schema-$(date +%Y%m%d-%H%M%S)" | tee /tmp/pinata_upload.log
IPFS_HASH=$(grep -o 'Qm[A-Za-z0-9]\{44\}\|baf[A-Za-z0-9]\{55,\}' /tmp/pinata_upload.log | head -1); \
if [ -n "$IPFS_HASH" ]; then \
    echo "IPFS Hash: $IPFS_HASH"; \
    echo "Getting gateway link..."; \
    SCHEMA_GATEWAY_LINK=$(~/.local/share/pinata/pinata gateways link "$IPFS_HASH" 2>/dev/null || echo "https://gateway.pinata.cloud/ipfs/$IPFS_HASH"); \
    echo "Direct IPFS Link: $SCHEMA_GATEWAY_LINK"; \
    echo "Public IPFS Link: https://ipfs.io/ipfs/$IPFS_HASH"; \
else \
    echo "Warning: Could not extract IPFS hash from upload output"; \
    cat /tmp/pinata_upload.log; \
fi
rm -f /tmp/pinata_upload.log

# Get attester from newton_prover_config.json in contracts directory for chain id 31337
# or from testnet_newton_prover_config.json in contracts directory for chain id 11155111 or 17000
if [[ "$chain_id" = "31337" ]]; then
    ATTESTER=$(grep -o 'task_generator_addr": "[^"]*"' ./contracts/newton_prover_config.json | sed 's/.*": "\([^"]*\)".*/\1/');
elif [[ "$chain_id" = "11155111" ]]; then
    ATTESTER=$(grep -o 'task_generator_addr": "[^"]*"' ./contracts/testnet_newton_prover_config.json | sed 's/.*": "\([^"]*\)".*/\1/');
elif [[ "$chain_id" = "17000" ]]; then
    ATTESTER=$(grep -o 'task_generator_addr": "[^"]*"' ./contracts/testnet_newton_prover_config.json | sed 's/.*": "\([^"]*\)".*/\1/');
fi

echo "Parsed attester address: $ATTESTER"

# Create policy_uris.json
cat > $out/policy_uris.json << EOF
{
  "policyDataLocation": "$WASM_GATEWAY_LINK",
  "policyDataArgs": "$WASM_ARGS_GATEWAY_LINK",
  "attester": "$ATTESTER",
  "policyUri": "$POLICY_GATEWAY_LINK",
  "schemaUri": "$SCHEMA_GATEWAY_LINK",
  "entrypoint": "$entrypoint",
  "policyMetadataUri": "$POLICY_METADATA_GATEWAY_LINK",
  "policyDataMetadataUri": "$POLICY_DATA_METADATA_GATEWAY_LINK"
}
EOF

echo "Created policy_uris.json with the following content:"
cat $out/policy_uris.json
