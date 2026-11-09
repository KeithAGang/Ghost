// Package report writes JSONL records and a human-readable summary.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/KeithAGang/Ghost/internal/probe"
)

// JSONL writes one JSON object per line. Write is safe for concurrent use.
type JSONL struct {
	enc *json.Encoder
	mu  sync.Mutex
}

func NewJSONL(w io.Writer) *JSONL {
	return &JSONL{enc: json.NewEncoder(w)}
}

func (j *JSONL) Write(result probe.Result) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.enc.Encode(result)
}

// Percentiles are nearest-rank timings in milliseconds.
type Percentiles struct {
	P50 int64 `json:"p50_ms"`
	P95 int64 `json:"p95_ms"`
}

// Summary aggregates probe results.
type Summary struct {
	Total     int `json:"total"`
	Reachable int `json:"reachable"`
	HTTPOK    int `json:"http_ok"`
	OK        int `json:"ok"`
	Failed    int `json:"failed"`

	ByStage  map[string]int `json:"by_stage,omitempty"`
	ByStatus map[string]int `json:"by_status,omitempty"`
	ByError  map[string]int `json:"by_error,omitempty"`
	ByColo   map[string]int `json:"by_colo,omitempty"`
	ByFamily map[string]int `json:"by_family,omitempty"`

	TCP  Percentiles `json:"tcp"`
	TLS  Percentiles `json:"tls"`
	TTFB Percentiles `json:"ttfb"`

	tcp  []int64
	tls  []int64
	ttfb []int64
}

// Add records one result.
func (s *Summary) Add(r probe.Result) {
	if s.ByStage == nil {
		s.ByStage = make(map[string]int)
		s.ByStatus = make(map[string]int)
		s.ByError = make(map[string]int)
		s.ByColo = make(map[string]int)
		s.ByFamily = make(map[string]int)
	}

	s.Total++
	if r.Reachable {
		s.Reachable++
	} else {
		s.Failed++
	}
	if r.HTTPOK {
		s.HTTPOK++
	}
	if r.OK {
		s.OK++
	}
	if r.Stage != "" {
		s.ByStage[r.Stage]++
	}
	if r.Status != 0 {
		s.ByStatus[fmt.Sprintf("%d", r.Status)]++
	}
	if r.ErrorKind != "" {
		s.ByError[r.ErrorKind]++
	}
	if r.Family != "" {
		s.ByFamily[r.Family]++
	}
	if r.Trace != nil {
		if colo := r.Trace["colo"]; colo != "" {
			s.ByColo[colo]++
		}
	}
	if r.TCPMS > 0 {
		s.tcp = append(s.tcp, r.TCPMS)
	}
	if r.TLSMS > 0 {
		s.tls = append(s.tls, r.TLSMS)
	}
	if r.TTFBMS > 0 {
		s.ttfb = append(s.ttfb, r.TTFBMS)
	}
}

// Finalize computes percentiles. Call once after all results are added.
func (s *Summary) Finalize() {
	s.TCP = percentiles(s.tcp)
	s.TLS = percentiles(s.tls)
	s.TTFB = percentiles(s.ttfb)
}

// String renders a compact summary for stderr.
func (s Summary) String() string {
	var b strings.Builder
	rate := 0.0
	if s.Total > 0 {
		rate = 100 * float64(s.OK) / float64(s.Total)
	}
	fmt.Fprintf(&b, "total=%d reachable=%d http_ok=%d ok=%d failed=%d ok_rate=%.1f%%\n",
		s.Total, s.Reachable, s.HTTPOK, s.OK, s.Failed, rate)
	writeCounts(&b, "stage", s.ByStage)
	writeCounts(&b, "status", s.ByStatus)
	writeCounts(&b, "error", s.ByError)
	writeCounts(&b, "colo", s.ByColo)
	writeCounts(&b, "family", s.ByFamily)
	fmt.Fprintf(&b, "tcp_ms p50=%d p95=%d\n", s.TCP.P50, s.TCP.P95)
	fmt.Fprintf(&b, "tls_ms p50=%d p95=%d\n", s.TLS.P50, s.TLS.P95)
	fmt.Fprintf(&b, "ttfb_ms p50=%d p95=%d\n", s.TTFB.P50, s.TTFB.P95)
	return b.String()
}

func writeCounts(b *strings.Builder, label string, counts map[string]int) {
	if len(counts) == 0 {
		return
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	fmt.Fprintf(b, "%s:", label)
	for _, key := range keys {
		fmt.Fprintf(b, " %s=%d", key, counts[key])
	}
	b.WriteByte('\n')
}

func percentiles(values []int64) Percentiles {
	if len(values) == 0 {
		return Percentiles{}
	}
	sorted := append([]int64(nil), values...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	return Percentiles{
		P50: nearestRank(sorted, 50),
		P95: nearestRank(sorted, 95),
	}
}

func nearestRank(sorted []int64, percentile int) int64 {
	index := len(sorted) * percentile / 100
	if index >= len(sorted) {
		index = len(sorted) - 1
	}
	return sorted[index]
}
