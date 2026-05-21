# selfdef — top-level Makefile
#
# Thin wrapper around cargo + the coherence harness. The canonical
# build and test surface lives in Cargo + scripts/test/; this file
# is the operator-facing entry-point so `make coherence`, `make test`,
# `make build` all work from a fresh clone without operators having
# to remember the exact incantations.
#
# Source: SDD-030 Deliverable 5 / MS045 R-rows.

.DEFAULT_GOAL := help

CARGO ?= cargo
BASH  ?= bash

.PHONY: help build test coherence clippy fmt fmt-check clean watchdogs install-systemd

help:
	@echo "selfdef Makefile — operator-facing entry-points"
	@echo
	@echo "  make build         cargo build --workspace"
	@echo "  make test          cargo test --workspace (unit + integration)"
	@echo "  make coherence     full 13-layer L1+L2+cargo coherence harness"
	@echo "  make watchdogs     cargo test for the four-watchdog set crates"
	@echo "  make clippy        cargo clippy --workspace --no-deps"
	@echo "  make fmt           cargo fmt --all"
	@echo "  make fmt-check     cargo fmt --all -- --check (CI gate)"
	@echo "  make clean         cargo clean"
	@echo
	@echo "Authoritative coherence entry-point: scripts/test/coherence.sh"
	@echo "SDD source: docs/sdd/030-ux-coherence-test-harness.md"

build:
	$(CARGO) build --workspace

test:
	$(CARGO) test --workspace

# Full L1 + L2 + cargo coherence harness — see SDD-030.
# Runs every L1 gate, every L2 bats suite, and the four-watchdog cargo
# test set. Exit-zero only if every layer passes. The same harness CI
# runs on every push/PR + as the release pre-build gate.
coherence:
	$(BASH) scripts/test/coherence.sh

# Sub-target: just the four-watchdog set cargo unit suites (faster
# inner loop than full `make test`).
watchdogs:
	$(CARGO) test --quiet \
	    -p selfdef-friction-audit-mirror \
	    -p selfdef-friction-audit \
	    -p selfdef-perimeter-mirror \
	    -p selfdef-perimeter \
	    -p selfdef-guardian-mirror \
	    -p selfdef-guardian \
	    -p selfdef-scheduler-mirror \
	    -p selfdef-scheduler \
	    -p selfdef-api

clippy:
	$(CARGO) clippy --workspace --no-deps -- -D warnings

fmt:
	$(CARGO) fmt --all

fmt-check:
	$(CARGO) fmt --all -- --check

clean:
	$(CARGO) clean
