.PHONY: build vet run clean

BIN := bin/pjeheadless
MAIN := ./cmd/pjeheadless

build:
	go build -o $(BIN) $(MAIN)

vet:
	go vet ./...

run: build
	./$(BIN)

clean:
	rm -f $(BIN)
