.PHONY: build build-token vet test test-race proto run clean

BIN  := bin/pjeheadless
MAIN := ./cmd/pjeheadless

# proto generates gRPC stubs from proto/signer.proto.
# Requires: protoc, protoc-gen-go, protoc-gen-go-grpc.
# SECURITY: generated server uses plain TCP by default; see proto/gen.sh.
proto:
	bash proto/gen.sh

build:
	go build -o $(BIN) $(MAIN)

build-token:
	go build -tags token -o $(BIN) $(MAIN)

vet:
	go vet ./...

test:
	go test ./...

test-race:
	go test -race ./internal/grpcsigner/ ./internal/signer/

run: build
	./$(BIN)

clean:
	rm -f $(BIN)
