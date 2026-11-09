package probe

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestParseTrace(t *testing.T) {
	body := []byte("fl=123abc\nh=www.cloudflare.com\nip=203.0.113.1\ncolo=FRA\nwarp=off\ngateway=off\n")
	trace := ParseTrace(body)
	if trace["colo"] != "FRA" || trace["warp"] != "off" || trace["gateway"] != "off" {
		t.Fatalf("unexpected trace: %#v", trace)
	}
	if trace := ParseTrace(nil); trace != nil {
		t.Fatalf("empty body should return nil, got %#v", trace)
	}
}

func TestClassify(t *testing.T) {
	if got := Classify("tcp", context.DeadlineExceeded); got != "tcp_deadline" {
		t.Fatalf("deadline: got %q", got)
	}
	if got := Classify("tcp", &net.OpError{Op: "dial", Err: errors.New("connection refused")}); got != "tcp_refused" {
		t.Fatalf("refused: got %q", got)
	}
	if got := Classify("tls", errors.New("EOF")); got != "tls_eof" {
		t.Fatalf("eof: got %q", got)
	}
	if got := Classify("http", nil); got != "" {
		t.Fatalf("nil: got %q", got)
	}
}
