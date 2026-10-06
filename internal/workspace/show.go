package workspace

import (
	"fmt"
	"os/exec"
	"strings"
)

// Show reads properties of the service unit unit, as Systemctl does.
type Show func(unit string, props ...string) (map[string]string, error)

// Systemctl reads props of <unit>.service with systemctl show; a
// property missing from the output is an error.
func Systemctl(unit string, props ...string) (map[string]string, error) {
	out, err := exec.Command("systemctl", "show", "-p", strings.Join(props, ","), unit+".service").Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	p := parseShow(string(out))
	for _, k := range props {
		if _, ok := p[k]; !ok {
			return nil, fmt.Errorf("systemctl show %s: no %s", unit, k)
		}
	}
	return p, nil
}

func parseShow(s string) map[string]string {
	p := map[string]string{}
	for _, line := range strings.Split(s, "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			p[k] = v
		}
	}
	return p
}

// Inactive reports whether the unit of p is inactive or failed (a unit
// systemd no longer knows is inactive too): its processes and mount
// namespace are gone. A missing LoadState or any other ActiveState,
// missing included, is not inactive.
func Inactive(p map[string]string) bool {
	return p["LoadState"] != "" && (p["ActiveState"] == "inactive" || p["ActiveState"] == "failed")
}
