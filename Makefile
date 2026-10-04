VERSION ?= dev
GOFLAGS = -trimpath
LDFLAGS = -s -w -X main.buildVersion=$(VERSION)
BINS    = luk lukd luk-job

.PHONY: all build $(BINS) test checkmk vet clean

all: vet test checkmk build

build: $(BINS)

$(BINS):
	CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $@ ./cmd/$@

test:
	go test -race ./...

# The Checkmk check is Python; skipped without python3.
checkmk:
	@if command -v python3 >/dev/null; then \
		python3 -B -m unittest discover -s contrib/checkmk; \
	else \
		echo "python3 not found, checkmk tests skipped"; \
	fi

vet:
	go vet ./...
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt needed"; exit 1; }

clean:
	rm -f $(BINS)
