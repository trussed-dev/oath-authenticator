# Copyright (C) 2022 Nitrokey GmbH
# SPDX-License-Identifier: CC0-1.0

FUZZ_DURATION?="0"
FUZZ_JOBS?=$(shell nproc)
.NOTPARALLEL:

.PHONY: check
check:
	reuse lint

corpus: corpus.tar.gz
	tar xf $<

.PHONY: fuzz
fuzz:
	nice cargo +nightly fuzz run --jobs ${FUZZ_JOBS} fuzz_target_1 corpus -- -max_total_time=${FUZZ_DURATION}

.PHONY: fuzz-cov
fuzz-cov:
	cargo +nightly fuzz coverage fuzz_target_1 corpus
	$(MAKE) fuzz-cov-show

LLVMCOV=~/.rustup/toolchains/nightly-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov
.PHONY: fuzz-cov-show
fuzz-cov-show:
	$(LLVMCOV) show --format=html \
		--instr-profile=coverage/fuzz_target_1/coverage.profdata \
		 ${CARGO_TARGET_DIR}/x86_64-unknown-linux-gnu/release/fuzz_target_1 \
		> fuzz_coverage.html

.PHONY: ci
ci: check

.PHONY: setup
setup:
	rustup component add clippy rustfmt && rustup toolchain install nightly
	rustup component add llvm-tools-preview
	cargo install cargo-tarpaulin cargo-fuzz --profile release
	python3 -m pip install reuse
