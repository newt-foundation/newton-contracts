#!/bin/bash

chain_id=$1

# Function to get value from deployment data
get_deployment_value() {
    local key="$1"
    echo "$deployment_data" | jq -r ".addresses.$key // empty"
}

# Read the entire deployment JSON
deployment_data=$(cat script/deployments/newton-prover/$chain_id.json)

# Detect shell and use appropriate syntax
if [[ -n "$ZSH_VERSION" ]]; then
    # ZSH version
    typeset -A deployment
    while IFS='=' read -r key value; do
        [[ -n "$key" ]] && deployment["$key"]="$value"
    done < <(jq -r '.addresses | to_entries[] | "\(.key)=\(.value)"' script/deployments/newton-prover/$chain_id.json)
else
    # Try bash associative arrays (bash 4+)
    if declare -A deployment 2>/dev/null; then
        while IFS='=' read -r key value; do
            [[ -n "$key" ]] && deployment["$key"]="$value"
        done < <(jq -r '.addresses | to_entries[] | "\(.key)=\(.value)"' script/deployments/newton-prover/$chain_id.json)
    else
        # Bash 3 fallback: use regular arrays and functions
        deployment_keys=()
        deployment_values=()
        while IFS='=' read -r key value; do
            if [[ -n "$key" ]]; then
                deployment_keys+=("$key")
                deployment_values+=("$value")
            fi
        done < <(jq -r '.addresses | to_entries[] | "\(.key)=\(.value)"' script/deployments/newton-prover/$chain_id.json)
        
        # Override the get_deployment_value function for Bash 3
        get_deployment_value() {
            local key="$1"
            for i in "${!deployment_keys[@]}"; do
                if [[ "${deployment_keys[$i]}" == "$key" ]]; then
                    echo "${deployment_values[$i]}"
                    return 0
                fi
            done
            echo ""
        }
    fi
fi

# Function to get value from deployment data
get_core_deployment_value() {
    local key="$1"
    echo "$core_deployment_data" | jq -r ".addresses.$key // empty"
}

# Read the core deployment JSON
core_deployment_data=$(cat script/deployments/core/$chain_id.json)

# Detect shell and use appropriate syntax
if [[ -n "$ZSH_VERSION" ]]; then
    # ZSH version
    typeset -A core_deployment
    while IFS='=' read -r key value; do
        [[ -n "$key" ]] && core_deployment["$key"]="$value"
    done < <(jq -r '.addresses | to_entries[] | "\(.key)=\(.value)"' script/deployments/core/$chain_id.json)
else
    # Try bash associative arrays (bash 4+)
    if declare -A core_deployment 2>/dev/null; then
        while IFS='=' read -r key value; do
            [[ -n "$key" ]] && core_deployment["$key"]="$value"
        done < <(jq -r '.addresses | to_entries[] | "\(.key)=\(.value)"' script/deployments/core/$chain_id.json)
    else
        # Bash 3 fallback: use regular arrays and functions
        core_deployment_keys=()
        core_deployment_values=()
        while IFS='=' read -r key value; do
            if [[ -n "$key" ]]; then
                core_deployment_keys+=("$key")
                core_deployment_values+=("$value")
            fi
        done < <(jq -r '.addresses | to_entries[] | "\(.key)=\(.value)"' script/deployments/core/$chain_id.json)
        
        # Override the get_core_deployment_value function for Bash 3
        get_core_deployment_value() {
            local key="$1"
            for i in "${!core_deployment_keys[@]}"; do
                if [[ "${core_deployment_keys[$i]}" == "$key" ]]; then
                    echo "${core_deployment_values[$i]}"
                    return 0
                fi
            done
            echo ""
        }
    fi
fi