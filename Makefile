HOST ?= 0.0.0.0
PORT ?= 3000
LOCAL_ENCLAVE_DIR ?= /tmp/dlc-verify-tvc-local-enclave
EPHEMERAL_FILE ?= $(LOCAL_ENCLAVE_DIR)/qos.ephemeral.key

.PHONY: all
all: build

.PHONY: build
build:
	cargo build --locked --all

.PHONY: test
test: build
	cargo test --locked --all-targets

.PHONY: fmt
fmt:
	cargo fmt

.PHONY: lint
lint:
	cargo clippy --version
	cargo clippy --locked --all-targets -- -D warnings

# Generate keys to simulate QOS control.
.PHONY: local-keys
local-keys:
	mkdir -p $(LOCAL_ENCLAVE_DIR)
	test -f $(EPHEMERAL_FILE) || openssl rand -hex 32 > $(EPHEMERAL_FILE)

.PHONY: run
run: local-keys
	cargo run --bin dlc-verify-tvc -- \
	--host $(HOST) \
	--port $(PORT) \
	--ephemeral-file $(EPHEMERAL_FILE)

out/dlc-verify-tvc/index.json: \
	Cargo.lock Cargo.toml rust-toolchain.toml $(shell find images/dlc-verify-tvc crates -type f ! -path '*/target/*')
	$(call build,dlc-verify-tvc)

out/mint-attester/index.json: \
	Cargo.lock Cargo.toml rust-toolchain.toml $(shell find images/mint-attester crates -type f ! -path '*/target/*')
	$(call build,mint-attester)

define build_context
$$( \
	mkdir -p out; \
	self=$(1); \
	for each in $$(find out/ -maxdepth 2 -name index.json); do \
    	package=$$(basename $$(dirname $${each})); \
    	if [ "$${package}" = "$${self}" ]; then continue; fi; \
    	printf -- ' --build-context %s=oci-layout://./out/%s' "$${package}" "$${package}"; \
	done; \
)
endef

,:=,
define build
	$(eval NAME := $(1))
	$(eval TYPE := $(if $(2),$(2),dir))
	$(eval REGISTRY := lygoslabs-dlc-verify-tvc)
	$(eval PLATFORM := linux/amd64)
	DOCKER_BUILDKIT=1 \
	SOURCE_DATE_EPOCH=1 \
	BUILDKIT_MULTIPLATFORM=1 \
	docker build \
		--build-arg VERSION=$(VERSION) \
		--tag $(REGISTRY)/$(NAME) \
		--progress=plain \
		--platform=$(PLATFORM) \
		--label "org.opencontainers.image.source=https://github.com/LygosLabs/dlc-verify-tvc" \
		$(if $(filter common,$(NAME)),,$(call build_context,$(1))) \
		$(if $(filter 1,$(NOCACHE)),--no-cache) \
		--output "\
			type=oci,\
			$(if $(filter dir,$(TYPE)),tar=false$(,)) \
			rewrite-timestamp=true,\
			force-compression=true,\
			name=$(NAME),\
			$(if $(filter tar,$(TYPE)),dest=$@") \
			$(if $(filter dir,$(TYPE)),dest=out/$(NAME)") \
		-f images/$(NAME)/Containerfile \
		.
endef
