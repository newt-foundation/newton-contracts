#!/bin/bash

# Default values
chain_id=""
policy_params_file=""
policy_address=""

# Parse command line arguments
while getopts "c:p:a:h" opt; do
    case $opt in
        c)
            chain_id="$OPTARG"
            ;;
        p)
            policy_params_file="$OPTARG"
            ;;
        a)
            policy_address="$OPTARG"
            ;;
        h)
            echo "Usage: $0 -c <chain_id> -p <policy_params_file> -a <policy_address>"
            exit 0
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
    esac
done

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

OUTPUT=$(PRIVATE_KEY=$PRIVATE_KEY POLICY_PARAM_PATH=$policy_params_file POLICY_ADDRESS=$policy_address \
    forge script script/PolicyClientDeployer.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast --slow)

echo "Policy client deployed successfully"

echo $OUTPUT

policy_client_impl_address=$(echo "$OUTPUT" | grep "PolicyClient Implementation: " | awk '{print $NF}')

# MockNewtonPolicyClient
forge verify-contract \
    --num-of-optimizations 200 --watch \
    --rpc-url $RPC_URL --verifier etherscan --etherscan-api-key $ETHERSCAN_API_KEY \
    --constructor-args $(cast abi-encode "constructor()") \
    $policy_client_impl_address ./examples/mock/MockNewtonPolicyClient.sol:MockNewtonPolicyClient
