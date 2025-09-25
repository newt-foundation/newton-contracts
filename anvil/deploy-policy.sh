#!/bin/bash

# Default values
chain_id=""
wasm_cid=""
wasm_args_cid=""
policy_cid=""
schema_cid=""
attester=""
entrypoint=""

# Parse command line arguments
while getopts "c:w:a:p:s:m:d:t:e:h" opt; do
    case $opt in
        c)
            chain_id="$OPTARG"
            ;;
        w)
            wasm_cid="$OPTARG"
            ;;
        a)
            wasm_args_cid="$OPTARG"
            ;;
        p)
            policy_cid="$OPTARG"
            ;;
        s)
            schema_cid="$OPTARG"
            ;;
        m)
            policy_metadata_cid="$OPTARG"
            ;;
        d)
            policy_data_metadata_cid="$OPTARG"
            ;;
        t)
            attester="$OPTARG"
            ;;
        e)
            entrypoint="$OPTARG"
            ;;
        h)
            echo "Usage: $0 -c <chain_id> -w <wasm_cid> -a <wasm_args_uri> -p <policyCid> -s <schemaCid> \
            -m <policy_metadata_cid> -d <policy_data_metadata_cid> -t <attester> -e <entrypoint>"
            echo "  -c: Chain ID"
            echo "  -w: WASM CID"
            echo "  -a: WASM Args CID"
            echo "  -p: Policy CID"
            echo "  -s: Schema CID"
            echo "  -m: Policy Metadata CID"
            echo "  -d: Policy Data Metadata CID"
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
if [ -z "$chain_id" ] || [ -z "$wasm_cid" ] || [ -z "$policy_cid" ] || [ -z "$schema_cid" ] || \
[ -z "$policy_metadata_cid" ] || [ -z "$policy_data_metadata_cid" ] || [ -z "$attester" ] || [ -z "$entrypoint" ]; then
    echo "Error: Required parameters are missing (only wasm_args_cid is optional)"
    echo "Usage: $0 -c <chain_id> -w <wasm_cid> -a <wasm_args_cid> -p <policyCid> -s <schemaCid> \
    -m <policy_metadata_cid> -d <policy_data_metadata_cid> -t <attester> -e <entrypoint>"
    exit 1
fi

# Use the parameters
echo "Chain ID: $chain_id"
echo "WASM CID: $wasm_cid"
echo "WASM Args CID: $wasm_args_cid"
echo "Policy CID: $policy_cid"
echo "Schema CID: $schema_cid"
echo "Policy Metadata CID: $policy_metadata_cid"
echo "Policy Data Metadata CID: $policy_data_metadata_cid"
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
POLICY_CIDS_PATH="${POLICY_CIDS_PATH:-policy_cids.json}"

# Create the JSON content
cat > "$POLICY_CIDS_PATH" << EOF
{
  "wasmCid": "$wasm_cid",
  "wasmArgsCid": "$wasm_args_cid",
  "policyCid": "$policy_cid",
  "schemaCid": "$schema_cid",
  "attester": "$attester",
  "entrypoint": "$entrypoint",
  "policyDataMetadataCid": "$policy_data_metadata_cid",
  "policyMetadataCid": "$policy_metadata_cid"
}
EOF

OUTPUT=$(PRIVATE_KEY=$PRIVATE_KEY POLICY_CIDS_PATH=$POLICY_CIDS_PATH \
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
