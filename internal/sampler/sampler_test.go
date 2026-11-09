package sampler

import (
	"net/netip"
	"testing"
)

func TestSampleStaysInPrefix(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("104.16.0.0/13"),
		netip.MustParsePrefix("2606:4700::/32"),
	}
	s := New(prefixes, 42)
	got, err := s.Sample(200)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 200 {
		t.Fatalf("got %d candidates, want 200", len(got))
	}
	for _, candidate := range got {
		if !candidate.Prefix.Contains(candidate.Addr) {
			t.Fatalf("%s is not inside %s", candidate.Addr, candidate.Prefix)
		}
	}
}

func TestDeterministicSeed(t *testing.T) {
	prefix := netip.MustParsePrefix("104.16.0.0/13")
	a, err := New([]netip.Prefix{prefix}, 7).Sample(20)
	if err != nil {
		t.Fatal(err)
	}
	b, err := New([]netip.Prefix{prefix}, 7).Sample(20)
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		if a[i].Addr != b[i].Addr {
			t.Fatalf("index %d differs: %s vs %s", i, a[i].Addr, b[i].Addr)
		}
	}
}

func TestSamplePerPrefix(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("104.16.0.0/13"),
		netip.MustParsePrefix("172.64.0.0/13"),
		netip.MustParsePrefix("2606:4700::/32"),
	}
	got, err := New(prefixes, 9).SamplePerPrefix(5)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(prefixes)*5 {
		t.Fatalf("got %d candidates, want %d", len(got), len(prefixes)*5)
	}
}

func TestSmallPrefixRunsOut(t *testing.T) {
	prefix := netip.MustParsePrefix("104.18.0.1/32")
	if _, err := New([]netip.Prefix{prefix}, 1).SamplePerPrefix(2); err == nil {
		t.Fatal("expected a unique-address error for a /32 sampled twice")
	}
}

func TestEnumerateSmallPrefix(t *testing.T) {
	prefix := netip.MustParsePrefix("104.18.0.0/30")
	got, err := New([]netip.Prefix{prefix}, 1).Enumerate(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("got %d addresses, want 4", len(got))
	}
	if got[0].Addr.String() != "104.18.0.0" || got[3].Addr.String() != "104.18.0.3" {
		t.Fatalf("unexpected enumeration: %v", got)
	}
	if _, err := New([]netip.Prefix{prefix}, 1).Enumerate(3); err == nil {
		t.Fatal("expected the enumeration limit to be enforced")
	}
}
