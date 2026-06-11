MAKEFLAGS += --warn-undefined-variables
SHELL := /bin/bash
.SHELLFLAGS := -o pipefail -euc
.DEFAULT_GOAL := test

.PHONY: deps test cov lint copywriteheaders tidy

deps:
	@go install github.com/hashicorp/copywrite@b3e6599f43beff698f471c6f46888045453fa030 # v0.25.3
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@c0d3ddc9cf3faa61a4e378e879ece580256d76e5 # v2.12.2

test:
	go test -v -race -timeout=60s -parallel=10 ./...

# cov runs tests with a coverage profile
cov:
	go test -v -race -timeout=60s -parallel=10 ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out

# lint covers go vet and go fmt
lint:
	golangci-lint run

# make sure our copyright headers are correct
copywriteheaders:
	copywrite headers --plan

# make sure go.mod/sum are up to date
tidy:
	go mod tidy
	@if (git status --porcelain | grep -Eq "go\.(mod|sum)"); then \
		echo go.mod or go.sum needs updating; \
		git --no-pager diff go.mod; \
		git --no-pager diff go.sum; \
		exit 1; fi
