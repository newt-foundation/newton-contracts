PHONY: reset-anvil

# Default values
chain_id ?= 31337
block_time ?= 0
out ?= .

__TESTING__: ##

reset_anvil:
	-docker stop anvil
	-docker rm anvil

start_docker:
	$(MAKE) reset_anvil
	@if [ $(block_time) -gt 0 ]; then \
		echo "Starting anvil with block time $(block_time)"; \
		docker run -d --name anvil -p 8545:8545 --entrypoint anvil \
			ghcr.io/foundry-rs/foundry:latest --host 0.0.0.0 --block-time $(block_time); \
	else \
		docker run -d --name anvil -p 8545:8545 --entrypoint anvil \
			ghcr.io/foundry-rs/foundry:latest --host 0.0.0.0; \
	fi
	sleep 2

build:
	forge build

tests:
	forge test

__DEPLOYMENT__: ##
	
# NOTE: if params are not provided, defaults are used.
upload-policy-to-ipfs:
	$(if $(json), \
		$(eval wasm_file := $(shell jq -r '.wasm_file // empty' $(json)) \)
		$(eval wasm_args_file_raw := $(shell jq -r '.wasm_args_file // empty' $(json)) \)
		$(eval wasm_args_file := $(if $(filter-out empty,$(wasm_args_file_raw)),$(if $(filter-out "",$(wasm_args_file_raw)),$(wasm_args_file_raw))) \)
		$(eval policy_file := $(shell jq -r '.policy_file // empty' $(json)) \)
		$(eval schema_file := $(shell jq -r '.schema_file // empty' $(json)) \)
		$(eval entrypoint := $(shell jq -r '.entrypoint // empty' $(json)) \)
		$(eval policy_metadata_file := $(shell jq -r '.policy_metadata_file // empty' $(json)) \)
		$(eval policy_data_metadata_file := $(shell jq -r '.policy_data_metadata_file // empty' $(json)) \)
	)
	@echo "Uploading policy to IPFS for chain_id: $(chain_id)"
	@echo "WASM File: $(wasm_file)"
	@echo "WASM Args File: $(wasm_args_file)"
	@echo "Policy File: $(policy_file)"
	@echo "Schema File: $(schema_file)"
	@echo "Entrypoint: $(entrypoint)"
	@echo "Policy Metadata File: $(policy_metadata_file)"
	@echo "Policy Data Metadata File: $(policy_data_metadata_file)"
	./scripts/upload-policy-to-ipfs.sh -c $(chain_id) -w $(wasm_file) $(if $(wasm_args_file),-a $(wasm_args_file) \)
	-p $(policy_file) -s $(schema_file) -e $(entrypoint) -m $(policy_metadata_file) -d $(policy_data_metadata_file) \
	-o $(out)

# NOTE: if params are not provided, defaults are used.
deploy-policy:
	$(if $(json), \
		$(eval wasm_uri := $(shell jq -r '.policyDataLocation // empty' $(json)) \)
		$(eval wasm_args_file_raw := $(shell jq -r '.policyDataArgs // empty' $(json)) \)
		$(eval wasm_args_file := $(if $(filter-out empty,$(wasm_args_file_raw)),$(if $(filter-out "",$(wasm_args_file_raw)),$(wasm_args_file_raw))) \)
		$(eval policy_uri := $(shell jq -r '.policyUri // empty' $(json)) \)
		$(eval schema_uri := $(shell jq -r '.schemaUri // empty' $(json)) \)
		$(eval policy_metadata_uri := $(shell jq -r '.policyMetadataUri // empty' $(json)) \)
		$(eval policy_data_metadata_uri := $(shell jq -r '.policyDataMetadataUri // empty' $(json)) \)
		$(eval entrypoint := $(shell jq -r '.entrypoint // empty' $(json)) \)
		$(eval attester := $(shell jq -r '.attester // empty' $(json)) \)
	) \
	./contracts/anvil/deploy-policy.sh -c $(chain_id) -t $(attester) -e $(entrypoint) -w $(wasm_uri) \
	$(if $(wasm_args_file),-a $(wasm_args_file)) -p $(policy_uri) -s $(schema_uri) -m $(policy_metadata_uri) -d $(policy_data_metadata_uri)

# NOTE: if params are not provided, defaults are used.
deploy-policy-client:
	./contracts/anvil/deploy-policy-client.sh -c $(chain_id) -p $(policy_params_file) -a $(policy_address)
