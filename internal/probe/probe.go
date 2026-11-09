// Package probe performs one rate-limited Cloudflare edge probe.
//
// The probe deliberately uses HTTP/1.1 over a manually established TLS
// connection. That makes TCP, TLS, and HTTP failures distinguishable, which is
// more useful for network research than a generic HTTP client error.
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// Target is the hostname and request to test.
type Target struct {
	Host    string
	Port    int
	Path    string
	Timeout time.Duration
}

// Result is one JSONL record.
type Result struct {
	IP        string `json:"ip"`
	CIDR      string `json:"cidr,omitempty"`
	Family    string `json:"family"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Path      string `json:"path"`
	At        string `json:"at"`
	Stage     string `json:"stage"`
	Reachable bool   `json:"reachable"`
	HTTPOK    bool   `json:"http_ok"`
	TraceOK   bool   `json:"trace_ok"`
	OK        bool   `json:"ok"`

	Status      int    `json:"status,omitempty"`
	ErrorKind   string `json:"error_kind,omitempty"`
	Error       string `json:"error,omitempty"`
	TCPMS       int64  `json:"tcp_ms,omitempty"`
	TLSMS       int64  `json:"tls_ms,omitempty"`
	TTFBMS      int64  `json:"ttfb_ms,omitempty"`
	TotalMS     int64  `json:"total_ms,omitempty"`
	HTTPProto   string `json:"http_proto,omitempty"`
	ALPN        string `json:"alpn,omitempty"`
	Server      string `json:"server,omitempty"`
	CFRay       string `json:"cf_ray,omitempty"`
	CFMitigated string `json:"cf_mitigated,omitempty"`
	Location    string `json:"location,omitempty"`

	AccessRedirect bool              `json:"access_redirect,omitempty"`
	Trace          map[string]string `json:"trace,omitempty"`
}

// Probe dials ip, performs TLS with target.Host as SNI, and sends one GET.
//
// OK means the probe got the expected Cloudflare edge response: a successful
// /cdn-cgi/trace, or an Access login redirect. Reachable means any HTTP
// response was received. A 403 is reachable but not OK.
func Probe(ctx context.Context, ip netip.Addr, prefix netip.Prefix, target Target) (r Result) {
	if target.Timeout <= 0 {
		target.Timeout = 8 * time.Second
	}
	if target.Port == 0 {
		target.Port = 443
	}
	if target.Path == "" {
		target.Path = "/"
	}

	family := "6"
	if ip.Is4() {
		family = "4"
	}
	r = Result{
		IP:     ip.String(),
		CIDR:   prefix.String(),
		Family: family,
		Host:   target.Host,
		Port:   target.Port,
		Path:   target.Path,
		At:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	start := time.Now()
	defer func() {
		r.TotalMS = time.Since(start).Milliseconds()
	}()

	dialer := net.Dialer{Timeout: target.Timeout, KeepAlive: 30 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(target.Port)))
	if err != nil {
		r.Stage = "tcp"
		r.ErrorKind = Classify("tcp", err)
		r.Error = err.Error()
		return r
	}
	defer conn.Close()
	r.TCPMS = time.Since(start).Milliseconds()
	_ = conn.SetDeadline(time.Now().Add(target.Timeout))

	tlsStart := time.Now()
	tlsConn := tls.Client(conn, &tls.Config{
		ServerName: target.Host,
		MinVersion: tls.VersionTLS12,
		NextProtos: []string{"http/1.1"},
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		r.Stage = "tls"
		r.ErrorKind = Classify("tls", err)
		r.Error = err.Error()
		return r
	}
	r.TLSMS = time.Since(tlsStart).Milliseconds()
	r.ALPN = tlsConn.ConnectionState().NegotiatedProtocol
	_ = tlsConn.SetDeadline(time.Now().Add(target.Timeout))

	request := fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Ghost/0.1 (network research)\r\nAccept: text/plain\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n",
		target.Path, target.Host,
	)
	if _, err := io.WriteString(tlsConn, request); err != nil {
		r.Stage = "http-write"
		r.ErrorKind = Classify("http-write", err)
		r.Error = err.Error()
		return r
	}

	resp, err := http.ReadResponse(
		bufio.NewReader(io.LimitReader(tlsConn, 1<<20)),
		&http.Request{Method: http.MethodGet},
	)
	if err != nil {
		r.Stage = "http-read"
		r.ErrorKind = Classify("http-read", err)
		r.Error = err.Error()
		return r
	}
	defer resp.Body.Close()

	r.Stage = "http"
	r.Reachable = true
	r.Status = resp.StatusCode
	r.HTTPOK = resp.StatusCode >= 200 && resp.StatusCode < 400
	r.HTTPProto = resp.Proto
	r.Server = resp.Header.Get("Server")
	r.CFRay = resp.Header.Get("CF-Ray")
	r.CFMitigated = resp.Header.Get("CF-Mitigated")
	r.Location = resp.Header.Get("Location")
	r.TTFBMS = time.Since(start).Milliseconds() - r.TCPMS - r.TLSMS
	if r.TTFBMS < 0 {
		r.TTFBMS = 0
	}

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	r.Trace = ParseTrace(body)
	r.TraceOK = resp.StatusCode == http.StatusOK &&
		r.CFRay != "" &&
		strings.Contains(string(body), "fl=")
	r.AccessRedirect = strings.Contains(strings.ToLower(r.Location), "cloudflareaccess.com")
	r.OK = r.TraceOK || r.AccessRedirect

	switch {
	case r.CFMitigated != "":
		r.ErrorKind = "cf_mitigated"
	case resp.StatusCode == http.StatusTooManyRequests:
		r.ErrorKind = "http_429"
	case resp.StatusCode == http.StatusForbidden:
		r.ErrorKind = "http_403"
	case resp.StatusCode >= 500:
		r.ErrorKind = "http_5xx"
	}
	return r
}

// ParseTrace parses Cloudflare's /cdn-cgi/trace key=value body.
func ParseTrace(body []byte) map[string]string {
	if len(body) == 0 {
		return nil
	}
	trace := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		trace[key] = value
	}
	if len(trace) == 0 {
		return nil
	}
	return trace
}

// Classify turns a transport error into a stable, low-cardinality label.
func Classify(stage string, err error) string {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return stage + "_deadline"
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return stage + "_timeout"
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		msg := strings.ToLower(opErr.Err.Error())
		switch {
		case strings.Contains(msg, "connection refused"):
			return stage + "_refused"
		case strings.Contains(msg, "connection reset"):
			return stage + "_reset"
		case strings.Contains(msg, "network is unreachable"):
			return stage + "_unreachable"
		case strings.Contains(msg, "no route to host"):
			return stage + "_no_route"
		case strings.Contains(msg, "broken pipe"):
			return stage + "_broken_pipe"
		case strings.Contains(msg, "eof"):
			return stage + "_eof"
		default:
			return stage + "_io"
		}
	}

	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return stage + "_cert"
	}
	var hostErr x509.HostnameError
	if errors.As(err, &hostErr) {
		return stage + "_hostname"
	}
	var authErr x509.UnknownAuthorityError
	if errors.As(err, &authErr) {
		return stage + "_unknown_authority"
	}
	var headerErr tls.RecordHeaderError
	if errors.As(err, &headerErr) {
		return stage + "_not_tls"
	}
	if strings.Contains(strings.ToLower(err.Error()), "eof") {
		return stage + "_eof"
	}
	return stage + "_error"
}
