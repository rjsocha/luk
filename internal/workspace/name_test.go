package workspace

import (
	"regexp"
	"strings"
	"testing"
)

func TestUnitNames(t *testing.T) {
	re := regexp.MustCompile(`^lukd-run-s3-upload-v2-x-[0-9a-f]{12}$`)
	if u := JobUnit("s3-upload.v2_x"); !re.MatchString(u) || !ValidUnit(u) {
		t.Fatalf("%q", u)
	}
	re = regexp.MustCompile(`^lukd-step-db-daily-3-[0-9a-f]{12}$`)
	if u := StepUnit("DB.Daily", 3); !re.MatchString(u) || !ValidUnit(u) {
		t.Fatalf("%q", u)
	}
	if u := StepUnit(strings.Repeat("p", 128), 99999); !ValidUnit(u) {
		t.Fatalf("long pipeline: %q (%d bytes)", u, len(u))
	}
	if u := JobUnit("a-"); !ValidUnit(u) {
		t.Fatalf("job a-: %q", u)
	}
	if u := StepUnit("p-", 1); !ValidUnit(u) {
		t.Fatalf("pipeline p-: %q", u)
	}
	if JobUnit("a") == JobUnit("a") {
		t.Fatal("unit names repeat")
	}
	if !regexp.MustCompile(`^lukd-workspace-[0-9a-f]{12}$`).MatchString(HelperUnit()) {
		t.Fatal(HelperUnit())
	}
}

func TestValidUnit(t *testing.T) {
	for u, ok := range map[string]bool{
		"lukd-run-a-0123456789ab":                                true,
		"lukd-step-p-1-0123456789ab":                             true,
		"lukd-run-a--0123456789ab":                               true,
		"lukd-run-a-0123456789AB":                                false,
		"lukd-run-a-0123456789a":                                 false,
		"lukd-run--0123456789ab":                                 false,
		"lukd-other-a-0123456789ab":                              false,
		"lukd-run-a.b-0123456789ab":                              false,
		"lukd-run-../x-0123456789ab":                             false,
		"lukd-workspace-0123456789ab":                            false,
		"lukd-run-a-0123456789ab\n":                              false,
		"lukd-run-" + strings.Repeat("a", 218) + "-0123456789ab": true,
		"lukd-run-" + strings.Repeat("a", 219) + "-0123456789ab": false,
	} {
		if ValidUnit(u) != ok {
			t.Errorf("%q: want %v", u, ok)
		}
	}
	if got := Path("/var/lib/luk", "lukd-run-a-0123456789ab"); got != "/var/lib/luk/root/job/lukd-run-a-0123456789ab" {
		t.Fatal(got)
	}
}
