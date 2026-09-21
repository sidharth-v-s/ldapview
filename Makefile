.PHONY: build test integration vet run clean
build:
	go build -o bin/ldapview ./cmd/ldapview
test:
	go test ./...
vet:
	go vet ./...
# needs a reachable test server, see README
integration:
	go test -tags integration ./...
run: build
	./bin/ldapview
clean:
	rm -rf bin
