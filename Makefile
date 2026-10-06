VERSION ?= dev
GOFLAGS = -trimpath
LDFLAGS = -s -w -X main.buildVersion=$(VERSION)
BINS    = luk lukd luk-job

.PHONY: all build $(BINS) test checkmk vet vuln marketing thumbnail clean

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

# Known vulnerabilities in the code paths luk calls (needs network).
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest -show verbose ./...

# The demo recording: contrib/demo/luk.vhs played by asciinema-vhs (hopper
# package) into contrib/demo/luk.cast; nothing in it runs for real.
ASCINEMA_VHS ?= asciinema-vhs

marketing:
	$(ASCINEMA_VHS) record contrib/demo/luk.vhs -o contrib/demo/luk.cast --cols 120 --rows 30 --title "luk"

# The README shows doc/demo.svg, the thumbnail asciinema.org makes of the
# uploaded recording (DEMO_ID): GitHub's image proxy cannot fetch it from
# asciinema.org, so it is kept in the repository. Refresh after an upload.
DEMO_ID ?= 1267589

thumbnail:
	curl -fsS https://asciinema.org/a/$(DEMO_ID).svg -o doc/demo.svg

clean:
	rm -f $(BINS)
