# zdh — thin wrapper. The real logic lives in scripts/*.sh.
#
# That split is deliberate: Git Bash on Windows ships no make, so the two of us
# run `bash scripts/gate.sh` while a judge on Linux runs `make gate`. Both paths
# execute the same script, so there is no second implementation to drift.
#
# Recipe lines are tabs, not spaces.

.PHONY: all gate build verify test race deps-proof clean

all: gate

## gate: the full build gate — format, vet, build, test, race, zero-dependency proof
gate:
	bash scripts/gate.sh

## build: the reproducible build, into bin/zdh
build:
	bash scripts/build.sh

## verify: build twice and prove the two binaries hash identically
verify:
	bash scripts/build.sh --verify

## test: unit tests
test:
	go test ./...

## race: unit tests under the race detector
race:
	go test -race ./...

## deps-proof: regenerate deps-proof.txt from the built binary
deps-proof: build
	bash scripts/deps-proof.sh > deps-proof.txt
	@echo "wrote deps-proof.txt"

## clean: remove build output
clean:
	rm -rf bin
