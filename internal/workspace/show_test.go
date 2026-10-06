package workspace

import "testing"

func TestParseShow(t *testing.T) {
	p := parseShow("UID=61234\nGID=61234\nActiveState=active\nLoadState=loaded\nWorkingDirectory=/a=b\n")
	if p["UID"] != "61234" || p["ActiveState"] != "active" || p["WorkingDirectory"] != "/a=b" {
		t.Fatalf("%v", p)
	}
	for show, inactive := range map[string]bool{
		"LoadState=loaded\nActiveState=active\n":       false,
		"LoadState=loaded\nActiveState=deactivating\n": false,
		"LoadState=loaded\nActiveState=inactive\n":     true,
		"LoadState=loaded\nActiveState=failed\n":       true,
		"LoadState=not-found\nActiveState=inactive\n":  true,
		"LoadState=masked\nActiveState=active\n":       false,
		"LoadState=loaded\nActiveState=maintenance\n":  false,
		"LoadState=not-found\n":                        false,
		"ActiveState=inactive\n":                       false,
		"LoadState=\nActiveState=inactive\n":           false,
		"":                                             false,
	} {
		if Inactive(parseShow(show)) != inactive {
			t.Errorf("%q: want %v", show, inactive)
		}
	}
}
