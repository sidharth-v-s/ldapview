.PHONY: build test integration vet run clean
build:
	go build -o bin/ldapview ./cmd/ldapview
test:
	go test ./...
vet:
	go vet ./...
# needs a reachable LDAP server, e.g. LDAPVIEW_TEST_HOST=127.0.0.1 LDAPVIEW_TEST_PORT=389
integration:
	go test -tags integration ./...
run: build
	./bin/ldapview
clean:
	rm -rf bin
