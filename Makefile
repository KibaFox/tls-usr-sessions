export GO111MODULE = on

.PHONY: help clean build lint

help:
	@echo "Please use \`make <target>\` where <target> is one of"
	@echo "  clean          to clean up build artifacts"
	@echo "  build          to build the demo into the dist/ folder"
	@echo "  lint           to run linteres and static analysis on the code"
	@echo "  test           to run tests"

clean:
	rm -rf dist/

build: dist/tls-sess-demo

lint:
	golangci-lint run

test:
	ginkgo -v -r --randomizeAllSpecs --randomizeSuites --failOnPending

pb/session.pb.go: pb/session.proto
	protoc -I=pb --go_out=plugins=grpc:pb session.proto

dist/tls-sess-demo: $(shell find . -name '*.go')
	go build -o ./dist/tls-sess-demo ./cmd/tls-sess-demo
