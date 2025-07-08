#!/bin/bash

# Default values
chain_id=""
wasm_uri=""
wasm_args_uri=""
policy_uri=""
schema_uri=""
attester=""
entrypoint=""

# Parse command line arguments
while getopts "c:w:a:p:s:m:d:t:e:h" opt; do
    case $opt in
        c)
            chain_id="$OPTARG"
            ;;
        w)
            wasm_uri="$OPTARG"
            ;;
        a)
            wasm_args_uri="$OPTARG"
            ;;
        p)
            policy_uri="$OPTARG"
            ;;
        s)
            schema_uri="$OPTARG"
            ;;
        m)
            policy_metadata_uri="$OPTARG"
            ;;
        d)
            policy_data_metadata_uri="$OPTARG"
            ;;
        t)
            attester="$OPTARG"
            ;;
        e)
            entrypoint="$OPTARG"
            ;;
        h)
            echo "Usage: $0 -c <chain_id> -w <wasm_uri> -a <wasm_args_uri> -p <policy_uri> -s <schema_uri> \
            -m <policy_metadata_uri> -d <policy_data_metadata_uri> -t <attester> -e <entrypoint>"
            echo "  -c: Chain ID"
            echo "  -w: WASM URI"
            echo "  -a: WASM Args URI"
            echo "  -p: Policy URI"
            echo "  -s: Schema URI"
            echo "  -m: Policy Metadata URI"
            echo "  -d: Policy Data Metadata URI"
            echo "  -t: Attester"
            echo "  -e: Entrypoint"
            echo "  -h: Show this help message"
            exit 0
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
    esac
done

# Validate required parameters
if [ -z "$chain_id" ] || [ -z "$wasm_uri" ] || [ -z "$policy_uri" ] || [ -z "$schema_uri" ] || \
[ -z "$policy_metadata_uri" ] || [ -z "$policy_data_metadata_uri" ] || [ -z "$attester" ] || [ -z "$entrypoint" ]; then
    echo "Error: Required parameters are missing (only wasm_args_uri is optional)"
    echo "Usage: $0 -c <chain_id> -w <wasm_uri> -a <wasm_args_uri> -p <policy_uri> -s <schema_uri> \
    -m <policy_metadata_uri> -d <policy_data_metadata_uri> -t <attester> -e <entrypoint>"
    exit 1
fi

# Use the parameters
echo "Chain ID: $chain_id"
echo "WASM URI: $wasm_uri"
echo "WASM Args URI: $wasm_args_uri"
echo "Policy URI: $policy_uri"
echo "Schema URI: $schema_uri"
echo "Policy Metadata URI: $policy_metadata_uri"
echo "Policy Data Metadata URI: $policy_data_metadata_uri"
echo "Attester: $attester"
echo "Entrypoint: $entrypoint"

# Source the .env file
if [ "$chain_id" = "31337" ]; then
    ENV_FILE_PATH="contracts/.env.anvil"
else
    ENV_FILE_PATH="contracts/.env"
fi

set -euo pipefail

if [ -f "$ENV_FILE_PATH" ]; then
    source "$ENV_FILE_PATH"
fi

# cd to the directory of this script so that this can be run from anywhere
parent_path=$(
    cd "$(dirname "${BASH_SOURCE[0]}")"
    pwd -P
)
cd "$parent_path"

cd ../

# Create JSON file with URIs
POLICY_URIS_PATH="${POLICY_URIS_PATH:-policy_uris.json}"

# Create the JSON content
cat > "$POLICY_URIS_PATH" << EOF
{
  "policyDataLocation": "$wasm_uri",
  "policyDataArgs": "$wasm_args_uri",
  "policyUri": "$policy_uri",
  "schemaUri": "$schema_uri",
  "attester": "$attester",
  "entrypoint": "$entrypoint",
  "policyDataMetadataUri": "$policy_data_metadata_uri",
  "policyMetadataUri": "$policy_metadata_uri"
}
EOF

OUTPUT=$(PRIVATE_KEY=$PRIVATE_KEY POLICY_URIS_PATH=$POLICY_URIS_PATH \
    forge script script/PolicyDeployer.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --slow)

echo $OUTPUT

policy_impl_address=$(echo "$OUTPUT" | grep "Policy Implementation: " | awk '{print $NF}')
policy_address=$(echo "$OUTPUT" | grep "Policy: " | awk '{print $NF}')

echo "Policy deployed successfully"

# NewtonPolicy
forge verify-contract \
    --num-of-optimizations 200 --watch \
    --rpc-url $RPC_URL --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY \
    --constructor-args $(cast abi-encode "constructor()") \
    $policy_impl_address ./src/core/NewtonPolicy.sol:NewtonPolicy
