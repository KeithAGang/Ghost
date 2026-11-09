package cloudflare

import (
	"path/filepath"
	"testing"
)

func TestNewRejectsWrongFamily(t *testing.T) {
	if _, err := New([]string{"2400:cb00::/32"}, nil, "test"); err == nil {
		t.Fatal("expected an IPv6-in-IPv4-list error")
	}
	if _, err := New(nil, []string{"104.16.0.0/13"}, "test"); err == nil {
		t.Fatal("expected an IPv4-in-IPv6-list error")
	}
}

func TestFallbackIncludes104_18(t *testing.T) {
	set := Fallback()
	if len(set.IPv4) == 0 || len(set.IPv6) == 0 {
		t.Fatal("fallback should contain IPv4 and IPv6 prefixes")
	}

	// 104.18.0.0/16 is inside the published 104.16.0.0/13 block.
	for _, p := range set.IPv4 {
		if p.String() == "104.16.0.0/13" {
			return
		}
	}
	t.Fatal("fallback is missing 104.16.0.0/13")
}

func TestSaveLoadRoundTrip(t *testing.T) {
	set, err := New([]string{"104.16.0.0/13"}, []string{"2606:4700::/32"}, "test")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ranges.json")
	if err := SaveFile(path, set); err != nil {
		t.Fatal(err)
	}
	got, err := LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Source != "cache" {
		t.Fatalf("Source = %q, want cache", got.Source)
	}
	if len(got.IPv4) != 1 || got.IPv4[0].String() != "104.16.0.0/13" {
		t.Fatalf("unexpected IPv4 prefixes: %v", got.IPv4)
	}
	if len(got.IPv6) != 1 || got.IPv6[0].String() != "2606:4700::/32" {
		t.Fatalf("unexpected IPv6 prefixes: %v", got.IPv6)
	}
}

func TestPrefixesFamily(t *testing.T) {
	set := Fallback()
	for _, family := range []string{"4", "6", "all"} {
		prefixes, err := set.Prefixes(family)
		if err != nil {
			t.Fatalf("family %s: %v", family, err)
		}
		if len(prefixes) == 0 {
			t.Fatalf("family %s returned no prefixes", family)
		}
	}
	if _, err := set.Prefixes("5"); err == nil {
		t.Fatal("expected an invalid-family error")
	}
}
