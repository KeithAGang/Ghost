// Package cloudflare loads and samples Cloudflare's published edge ranges.
//
// The edge is anycast: an address identifies a Cloudflare data-center path,
// not a customer, zone, or Zero Trust application. Use the hostname as SNI.
package cloudflare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const APIURL = "https://api.cloudflare.com/client/v4/ips"

// Set is a validated snapshot of Cloudflare's edge prefixes.
type Set struct {
	IPv4      []netip.Prefix `json:"ipv4"`
	IPv6      []netip.Prefix `json:"ipv6"`
	FetchedAt time.Time      `json:"fetched_at"`
	Source    string         `json:"source,omitempty"`
}

// New parses and validates v4/v6 CIDR strings. Duplicate prefixes are removed.
func New(v4, v6 []string, source string) (Set, error) {
	p4, err := parsePrefixes(v4, 4)
	if err != nil {
		return Set{}, err
	}
	p6, err := parsePrefixes(v6, 6)
	if err != nil {
		return Set{}, err
	}
	if len(p4)+len(p6) == 0 {
		return Set{}, errors.New("no prefixes")
	}
	return Set{
		IPv4:      p4,
		IPv6:      p6,
		FetchedAt: time.Now().UTC(),
		Source:    source,
	}, nil
}

// Parse accepts a mixed list of IPv4 and IPv6 CIDRs.
func Parse(cidrs []string, source string) (Set, error) {
	var v4, v6 []string
	for _, raw := range cidrs {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return Set{}, fmt.Errorf("parse %q: %w", raw, err)
		}
		if p.Addr().Is4() {
			v4 = append(v4, raw)
		} else {
			v6 = append(v6, raw)
		}
	}
	return New(v4, v6, source)
}

// Prefixes returns the prefixes for family "4", "6", or "all".
func (s Set) Prefixes(family string) ([]netip.Prefix, error) {
	switch family {
	case "4":
		return append([]netip.Prefix(nil), s.IPv4...), nil
	case "6":
		return append([]netip.Prefix(nil), s.IPv6...), nil
	case "all":
		out := append([]netip.Prefix(nil), s.IPv4...)
		return append(out, s.IPv6...), nil
	default:
		return nil, fmt.Errorf("family must be 4, 6, or all, got %q", family)
	}
}

// Fetch reads the official range list from Cloudflare's API.
func Fetch(ctx context.Context, client *http.Client) (Set, error) {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, APIURL, nil)
	if err != nil {
		return Set{}, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return Set{}, fmt.Errorf("fetch ranges: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return Set{}, fmt.Errorf("fetch ranges: HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var payload struct {
		Success bool `json:"success"`
		Result  struct {
			IPv4 []string `json:"ipv4_cidrs"`
			IPv6 []string `json:"ipv6_cidrs"`
		} `json:"result"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&payload); err != nil {
		return Set{}, fmt.Errorf("decode ranges: %w", err)
	}
	if !payload.Success {
		msg := "unknown API error"
		if len(payload.Errors) > 0 {
			msg = payload.Errors[0].Message
		}
		return Set{}, fmt.Errorf("fetch ranges: %s", msg)
	}

	set, err := New(payload.Result.IPv4, payload.Result.IPv6, "api")
	if err != nil {
		return Set{}, err
	}
	set.FetchedAt = time.Now().UTC()
	return set, nil
}

// LoadFile reads a cached Set.
func LoadFile(path string) (Set, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Set{}, err
	}
	var set Set
	if err := json.Unmarshal(data, &set); err != nil {
		return Set{}, fmt.Errorf("decode %s: %w", path, err)
	}
	if err := validate(set); err != nil {
		return Set{}, fmt.Errorf("%s: %w", path, err)
	}
	set.Source = "cache"
	return set, nil
}

// SaveFile writes a Set atomically.
func SaveFile(path string, set Set) error {
	if path == "" {
		return errors.New("empty cache path")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(set, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	tmp, err := os.CreateTemp(filepath.Dir(path), ".ranges-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// DefaultCachePath returns a platform-appropriate cache location.
func DefaultCachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil || dir == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return ""
		}
		dir = filepath.Join(home, ".cache")
	}
	return filepath.Join(dir, "cfprobe", "ranges.json")
}

// Fallback returns the official list as of 2026-11-09. Refresh with the API.
func Fallback() Set {
	set, err := New(fallbackV4, fallbackV6, "builtin")
	if err != nil {
		panic(err) // static data; a failure here is a programming error
	}
	return set
}

var fallbackV4 = []string{
	"173.245.48.0/20",
	"103.21.244.0/22",
	"103.22.200.0/22",
	"103.31.4.0/22",
	"141.101.64.0/18",
	"108.162.192.0/18",
	"190.93.240.0/20",
	"188.114.96.0/20",
	"197.234.240.0/22",
	"198.41.128.0/17",
	"162.158.0.0/15",
	"104.16.0.0/13",
	"104.24.0.0/14",
	"172.64.0.0/13",
	"131.0.72.0/22",
}

var fallbackV6 = []string{
	"2400:cb00::/32",
	"2606:4700::/32",
	"2803:f800::/32",
	"2405:b500::/32",
	"2405:8100::/32",
	"2a06:98c0::/29",
	"2c0f:f248::/32",
}

func parsePrefixes(in []string, family int) ([]netip.Prefix, error) {
	seen := make(map[netip.Prefix]struct{}, len(in))
	out := make([]netip.Prefix, 0, len(in))
	for _, raw := range in {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		p, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("parse %q: %w", raw, err)
		}
		p = p.Masked()
		if family == 4 && !p.Addr().Is4() {
			return nil, fmt.Errorf("%q is not IPv4", raw)
		}
		if family == 6 && p.Addr().Is4() {
			return nil, fmt.Errorf("%q is not IPv6", raw)
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out, nil
}

func validate(set Set) error {
	for _, p := range set.IPv4 {
		if !p.IsValid() || !p.Addr().Is4() {
			return fmt.Errorf("invalid IPv4 prefix %q", p)
		}
	}
	for _, p := range set.IPv6 {
		if !p.IsValid() || p.Addr().Is4() {
			return fmt.Errorf("invalid IPv6 prefix %q", p)
		}
	}
	if len(set.IPv4)+len(set.IPv6) == 0 {
		return errors.New("no prefixes")
	}
	return nil
}
