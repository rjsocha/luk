package channel

import (
	"bytes"
	"encoding/binary"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestHeadRoundTrip(t *testing.T) {
	req := Request{Method: "PUT", Target: "/drop/a.txt", Header: http.Header{"Luk-Meta": {"x", "y"}}}
	resp := Response{Status: 201, Header: http.Header{"Location": {"/a.txt"}}}
	var b bytes.Buffer
	if err := WriteHead(&b, req); err != nil {
		t.Fatal(err)
	}
	if err := WriteHead(&b, resp); err != nil {
		t.Fatal(err)
	}
	b.WriteString("body")
	var gotReq Request
	var gotResp Response
	if err := ReadHead(&b, &gotReq); err != nil || !reflect.DeepEqual(gotReq, req) {
		t.Fatalf("request %+v %v", gotReq, err)
	}
	if err := ReadHead(&b, &gotResp); err != nil || !reflect.DeepEqual(gotResp, resp) {
		t.Fatalf("response %+v %v", gotResp, err)
	}
	if b.String() != "body" {
		t.Fatalf("body %q", b.String())
	}
}

func head(json string) *bytes.Buffer {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(len(json)))
	b.WriteString(json)
	return &b
}

func TestHeadLimits(t *testing.T) {
	big := Request{Method: "PUT", Target: "/" + strings.Repeat("a", 65536)}
	if err := WriteHead(new(bytes.Buffer), big); err == nil {
		t.Fatal("long head written")
	}
	long := `{"method":"PUT","target":"/` + strings.Repeat("a", 65536) + `"}`
	var r Request
	if err := ReadHead(head(long), &r); err == nil {
		t.Fatal("long head read")
	}
	for _, bad := range []string{
		`{"method":"PUT","target":"/","header":{},"extra":1}`,
		`{"method":"PUT"} {}`,
		``,
	} {
		if err := ReadHead(head(bad), &r); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	short := head(`{"method":"PUT"}`)
	short.Truncate(short.Len() - 1)
	if err := ReadHead(short, &r); err == nil {
		t.Fatal("short head accepted")
	}
}
