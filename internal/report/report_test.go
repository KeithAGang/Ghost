package report

import (
	"testing"

	"github.com/KeithAGang/Ghost/internal/probe"
)

func TestSummary(t *testing.T) {
	var summary Summary
	summary.Add(probe.Result{
		Stage: "http", Reachable: true, HTTPOK: true, TraceOK: true, OK: true,
		Status: 200, Family: "4", TCPMS: 10, TLSMS: 20, TTFBMS: 30,
		Trace: map[string]string{"colo": "FRA"},
	})
	summary.Add(probe.Result{
		Stage: "http", Reachable: true, Status: 302, ErrorKind: "access",
		Family: "4", TCPMS: 30, TLSMS: 40, TTFBMS: 50,
		Location: "https://example.cloudflareaccess.com/cdn-cgi/access/login",
	})
	summary.Add(probe.Result{
		Stage: "tcp", ErrorKind: "tcp_timeout", Family: "6",
		TCPMS: 80,
	})
	summary.Add(probe.Result{
		Stage: "tcp", ErrorKind: "tcp_timeout", Family: "6",
	})
	summary.Finalize()

	if summary.Total != 4 || summary.Reachable != 2 || summary.HTTPOK != 1 || summary.OK != 1 {
		t.Fatalf("unexpected counts: %+v", summary)
	}
	if summary.Failed != 2 {
		t.Fatalf("Failed = %d, want 2", summary.Failed)
	}
	if summary.ByColo["FRA"] != 1 {
		t.Fatalf("ByColo = %#v", summary.ByColo)
	}
	if summary.TCP.P50 != 30 || summary.TCP.P95 != 80 {
		t.Fatalf("TCP percentiles = %+v", summary.TCP)
	}
	if summary.TLS.P50 == 0 || summary.TTFB.P50 == 0 {
		t.Fatalf("expected TLS/TTFB percentiles: %+v %+v", summary.TLS, summary.TTFB)
	}
	if got := summary.String(); got == "" {
		t.Fatal("summary string is empty")
	}
}
