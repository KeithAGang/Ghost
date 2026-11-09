// Package sampler picks pseudo-random addresses from CIDR prefixes.
//
// It never enumerates a block. Sample N addresses across the selected prefixes,
// or use SamplePerPrefix for even coverage of each block.
package sampler

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net/netip"
)

// Candidate is one address and the prefix it came from.
type Candidate struct {
	Addr   netip.Addr
	Prefix netip.Prefix
}

// Sampler is deterministic for a given seed.
type Sampler struct {
	prefixes []netip.Prefix
	rng      *rand.Rand
	seen     map[netip.Addr]struct{}
}

// New returns a sampler over a copy of prefixes.
func New(prefixes []netip.Prefix, seed int64) *Sampler {
	return &Sampler{
		prefixes: append([]netip.Prefix(nil), prefixes...),
		rng:      rand.New(rand.NewSource(seed)),
		seen:     make(map[netip.Addr]struct{}),
	}
}

// Sample returns up to n unique addresses, choosing a random prefix for each.
// Prefixes are equally likely, so every published block gets coverage even
// when the blocks differ in size.
func (s *Sampler) Sample(n int) ([]Candidate, error) {
	if n <= 0 {
		return nil, fmt.Errorf("sample count must be greater than zero")
	}
	if len(s.prefixes) == 0 {
		return nil, fmt.Errorf("no prefixes")
	}

	out := make([]Candidate, 0, n)
	for attempts := 0; len(out) < n; attempts++ {
		if attempts > n*100 {
			return nil, fmt.Errorf("could only sample %d unique addresses", len(out))
		}
		p := s.prefixes[s.rng.Intn(len(s.prefixes))]
		c, ok := s.sampleOne(p)
		if ok {
			out = append(out, c)
		}
	}
	return out, nil
}

// Enumerate walks every address in every prefix, up to max addresses.
// It is deliberately bounded and is intended for small, authorized prefixes
// such as a single /24, not Cloudflare's full published ranges.
func (s *Sampler) Enumerate(max int) ([]Candidate, error) {
	if max <= 0 {
		return nil, fmt.Errorf("enumeration limit must be greater than zero")
	}
	if len(s.prefixes) == 0 {
		return nil, fmt.Errorf("no prefixes")
	}

	out := make([]Candidate, 0, max)
	for _, p := range s.prefixes {
		addr := p.Masked().Addr()
		for p.Contains(addr) {
			if len(out) >= max {
				return nil, fmt.Errorf("enumeration exceeds limit %d; narrow the prefix or raise -max", max)
			}
			out = append(out, Candidate{Addr: addr, Prefix: p})
			next := addr.Next()
			if !next.IsValid() {
				break
			}
			addr = next
		}
	}
	return out, nil
}

// SamplePerPrefix returns n unique addresses from every prefix.
func (s *Sampler) SamplePerPrefix(n int) ([]Candidate, error) {
	if n <= 0 {
		return nil, fmt.Errorf("per-prefix count must be greater than zero")
	}
	if len(s.prefixes) == 0 {
		return nil, fmt.Errorf("no prefixes")
	}

	out := make([]Candidate, 0, len(s.prefixes)*n)
	for _, p := range s.prefixes {
		for i := 0; i < n; i++ {
			c, ok := s.sampleOne(p)
			if !ok {
				return nil, fmt.Errorf("prefix %s has fewer than %d unique addresses", p, n)
			}
			out = append(out, c)
		}
	}
	s.rng.Shuffle(len(out), func(i, j int) {
		out[i], out[j] = out[j], out[i]
	})
	return out, nil
}

func (s *Sampler) sampleOne(p netip.Prefix) (Candidate, bool) {
	for attempts := 0; attempts < 100; attempts++ {
		addr := randomAddr(p, s.rng)
		if _, ok := s.seen[addr]; ok {
			continue
		}
		s.seen[addr] = struct{}{}
		return Candidate{Addr: addr, Prefix: p}, true
	}
	return Candidate{}, false
}

func randomAddr(p netip.Prefix, r *rand.Rand) netip.Addr {
	p = p.Masked()
	if p.Addr().Is4() {
		base := p.Addr().As4()
		start := uint64(binary.BigEndian.Uint32(base[:]))
		size := uint64(1) << (32 - p.Bits())
		offset := r.Uint64() % size
		value := start + offset

		var out [4]byte
		binary.BigEndian.PutUint32(out[:], uint32(value))
		return netip.AddrFrom4(out)
	}

	out := p.Addr().As16()
	for i := 0; i < len(out); i++ {
		bits := p.Bits() - i*8
		switch {
		case bits <= 0:
			out[i] = byte(r.Intn(256))
		case bits >= 8:
			// This byte is entirely part of the fixed prefix.
		default:
			mask := byte(0xff << (8 - bits))
			out[i] = (out[i] & mask) | (byte(r.Intn(256)) & ^mask)
		}
	}
	return netip.AddrFrom16(out)
}
