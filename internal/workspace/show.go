package workspace

import (
	"fmt"
	"os/exec"
	"strings"
)

// Show reads properties of the service unit unit, as Systemctl does.
type Show func(unit string, props ...string) (map[string]string, error)

// Systemctl reads props of <unit>.service with systemctl show.
func Systemctl(unit string, props ...string) (map[string]string, error) {
	out, err := exec.Command("systemctl", "show", "-p", strings.Join(props, ","), unit+".service").Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl show %s: %w", unit, err)
	}
	return parseShow(string(out)), nil
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

// Inactive reports whether the unit of p is not loaded, or inactive or
// failed: its processes and mount namespace are gone.
func Inactive(p map[string]string) bool {
	return p["LoadState"] != "loaded" || p["ActiveState"] == "inactive" || p["ActiveState"] == "failed"
}
