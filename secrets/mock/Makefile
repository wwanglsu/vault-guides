GOARCH = amd64

UNAME = $(shell uname -s)

ifndef OS
	ifeq ($(UNAME), Linux)
		OS = linux
	else ifeq ($(UNAME), Darwin)
		OS = darwin
	endif
endif

.DEFAULT_GOAL := all

all: fmt build start

build:
	GOOS=$(OS) GOARCH="$(GOARCH)" go build -o vault/plugins/mock cmd/mock/main.go

start:
	vault server -dev -dev-root-token-id=myroot -dev-plugin-dir=./vault/plugins

enable:
	vault secrets enable mock

clean:
	rm -f ./vault/plugins/mock

fmt:
	go fmt $$(go list ./...)

.PHONY: build clean fmt start enable