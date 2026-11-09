package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/KeithAGang/Ghost/internal/cloudflare"
	"github.com/KeithAGang/Ghost/internal/probe"
	"github.com/KeithAGang/Ghost/internal/report"
	"github.com/KeithAGang/Ghost/internal/runner"
	"github.com/KeithAGang/Ghost/internal/sampler"
)

const version = "0.1.0"

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }

func (s *stringList) Set(value string) error {
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			*s = append(*s, part)
		}
	}
	return nil
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("cfprobe: ")
	if err := run(); err != nil {
		log.Printf("error: %v", err)
		os.Exit(2)
	}
}

func run() error {
	var customCIDRs stringList

	host := flag.String("host", "www.cloudflare.com", "SNI and Host header")
	path := flag.String("path", "/cdn-cgi/trace", "request path")
	port := flag.Int("port", 443, "TCP port")
	family := flag.String("family", "4", "address family: 4, 6, or all")
	n := flag.Int("n", 30, "total IPs to sample")
	perCIDR := flag.Int("per-cidr", 0, "sample this many IPs from every selected prefix")
	enumerate := flag.Bool("enumerate", false, "walk every address in the selected prefixes, up to -max")
	maxIPs := flag.Int("max", 500, "hard cap on probes; protects against accidental mass scans")
	concurrency := flag.Int("conc", 2, "max probes in flight")
	rps := flag.Float64("rps", 1, "initial new probes per second")
	minRPS := flag.Float64("min-rps", 0.2, "minimum adaptive rate")
	maxRPS := flag.Float64("max-rps", 2, "maximum adaptive rate")
	timeout := flag.Duration("timeout", 8*time.Second, "per-probe timeout")
	cooldownEvery := flag.Int("cooldown-every", 25, "cool down after this many probes; 0 disables")
	cooldown := flag.Duration("cooldown", 5*time.Second, "base cool-down duration")
	seed := flag.Int64("seed", time.Now().UnixNano(), "random seed for reproducible samples")

	rangesSource := flag.String("ranges", "auto", "range source: auto, api, cache, builtin")
	cachePath := flag.String("cache", cloudflare.DefaultCachePath(), "range cache file")
	refresh := flag.Bool("refresh", false, "force an API refresh in auto mode")
	cidrsFile := flag.String("cidrs-file", "", "file with CIDRs, one per line; overrides -ranges")

	flag.Var(&customCIDRs, "cidr", "CIDR to probe; repeatable or comma-separated; overrides -ranges")

	resolve := flag.Bool("resolve", false, "resolve -host and probe its addresses instead of sampling ranges")
	dryRun := flag.Bool("dry-run", false, "print sampled candidates and exit without network probes")
	outPath := flag.String("out", "-", "JSONL output path, or - for stdout")
	showSummary := flag.Bool("summary", true, "print a summary to stderr")
	showVersion := flag.Bool("version", false, "print version and exit")

	flag.Parse()

	if *showVersion {
		fmt.Printf("cfprobe %s\n", version)
		return nil
	}

	if *host == "" {
		return errors.New("-host is required")
	}
	if !strings.HasPrefix(*path, "/") {
		return errors.New("-path must start with /")
	}
	if strings.ContainsAny(*host, "\r\n") || strings.ContainsAny(*path, "\r\n") {
		return errors.New("-host and -path cannot contain CR or LF")
	}
	if *port < 1 || *port > 65535 {
		return errors.New("-port must be between 1 and 65535")
	}
	if *n <= 0 && !*resolve && !*enumerate && *perCIDR == 0 {
		return errors.New("-n must be greater than zero")
	}
	if *perCIDR < 0 {
		return errors.New("-per-cidr cannot be negative")
	}
	if *maxIPs <= 0 {
		return errors.New("-max must be greater than zero")
	}
	if *concurrency < 1 {
		return errors.New("-conc must be at least 1")
	}
	if *rps <= 0 || *minRPS <= 0 || *maxRPS < *minRPS {
		return errors.New("-rps and -min-rps must be positive, and -max-rps must be >= -min-rps")
	}
	if *timeout <= 0 {
		return errors.New("-timeout must be greater than zero")
	}
	if *cooldown < 0 || *cooldownEvery < 0 {
		return errors.New("-cooldown and -cooldown-every cannot be negative")
	}
	if *family != "4" && *family != "6" && *family != "all" {
		return errors.New("-family must be 4, 6, or all")
	}
	if *resolve && (len(customCIDRs) > 0 || *cidrsFile != "" || *perCIDR > 0 || *enumerate) {
		return errors.New("-resolve cannot be combined with -cidr, -cidrs-file, -per-cidr, or -enumerate")
	}
	if *enumerate && *perCIDR > 0 {
		return errors.New("-enumerate cannot be combined with -per-cidr")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var (
		set         cloudflare.Set
		candidates  []sampler.Candidate
		prefixCount int
		v4Count     int
		v6Count     int
	)

	if *resolve {
		var err error
		candidates, err = resolveHost(ctx, *host, *family)
		if err != nil {
			return err
		}
		prefixCount = len(candidates)
		if len(candidates) > *maxIPs {
			return fmt.Errorf("resolved %d addresses, above -max %d", len(candidates), *maxIPs)
		}
		fmt.Fprintf(os.Stderr, "source=resolve mode=resolve addresses=%d family=%s host=%s\n",
			len(candidates), *family, *host)
	} else {
		var err error
		set, err = loadRanges(ctx, *rangesSource, *cachePath, *refresh, customCIDRs, *cidrsFile)
		if err != nil {
			return err
		}
		prefixes, err := set.Prefixes(*family)
		if err != nil {
			return err
		}
		if len(prefixes) == 0 {
			return fmt.Errorf("range set has no %s prefixes", *family)
		}

		s := sampler.New(prefixes, *seed)
		mode := "sample"
		switch {
		case *enumerate:
			mode = "enumerate"
			candidates, err = s.Enumerate(*maxIPs)
		case *perCIDR > 0:
			total := len(prefixes) * *perCIDR
			if total > *maxIPs {
				return fmt.Errorf("-per-cidr %d x %d prefixes = %d probes, above -max %d; raise -max deliberately",
					*perCIDR, len(prefixes), total, *maxIPs)
			}
			candidates, err = s.SamplePerPrefix(*perCIDR)
		default:
			if *n > *maxIPs {
				return fmt.Errorf("-n %d is above -max %d", *n, *maxIPs)
			}
			candidates, err = s.Sample(*n)
		}
		if err != nil {
			return err
		}
		prefixCount = len(prefixes)
		v4Count = len(set.IPv4)
		v6Count = len(set.IPv6)
		fmt.Fprintf(os.Stderr, "source=%s mode=%s prefixes=%d (v4=%d v6=%d) probes=%d family=%s host=%s\n",
			set.Source, mode, prefixCount, v4Count, v6Count, len(candidates), *family, *host)
	}

	out, closeOut, err := openOutput(*outPath)
	if err != nil {
		return err
	}
	defer closeOut()

	if *dryRun {
		for _, candidate := range candidates {
			if _, err := fmt.Fprintf(out, "%s\t%s\n", candidate.Addr, candidate.Prefix); err != nil {
				return err
			}
		}
		return nil
	}

	jsonl := report.NewJSONL(out)
	r := runner.New(runner.Config{
		Target: probe.Target{
			Host:    *host,
			Port:    *port,
			Path:    *path,
			Timeout: *timeout,
		},
		Concurrency:   *concurrency,
		Rate:          *rps,
		MinRate:       *minRPS,
		MaxRate:       *maxRPS,
		CooldownEvery: *cooldownEvery,
		Cooldown:      *cooldown,
		Seed:          *seed,
	})

	summary, runErr := r.Run(ctx, candidates, jsonl.Write)
	if *showSummary {
		fmt.Fprint(os.Stderr, summary.String())
	}
	return runErr
}

func loadRanges(ctx context.Context, source, cachePath string, refresh bool, cidrs []string, cidrsFile string) (cloudflare.Set, error) {
	var custom []string
	custom = append(custom, cidrs...)
	if cidrsFile != "" {
		fromFile, err := readCIDRFile(cidrsFile)
		if err != nil {
			return cloudflare.Set{}, err
		}
		custom = append(custom, fromFile...)
	}
	if len(custom) > 0 {
		return cloudflare.Parse(custom, "custom")
	}

	fetch := func() (cloudflare.Set, error) {
		return cloudflare.Fetch(ctx, &http.Client{Timeout: 15 * time.Second})
	}

	switch source {
	case "builtin":
		return cloudflare.Fallback(), nil

	case "cache":
		if cachePath == "" {
			return cloudflare.Set{}, errors.New("cache path is empty")
		}
		return cloudflare.LoadFile(cachePath)

	case "api":
		set, err := fetch()
		if err != nil {
			return cloudflare.Set{}, err
		}
		saveCache(cachePath, set)
		return set, nil

	case "auto":
		if !refresh && cachePath != "" {
			if set, err := cloudflare.LoadFile(cachePath); err == nil && time.Since(set.FetchedAt) < 30*24*time.Hour {
				return set, nil
			}
		}
		set, err := fetch()
		if err == nil {
			saveCache(cachePath, set)
			return set, nil
		}
		log.Printf("warning: fetch Cloudflare ranges: %v", err)
		if cachePath != "" {
			if cached, cacheErr := cloudflare.LoadFile(cachePath); cacheErr == nil {
				log.Printf("using cached ranges from %s", cachePath)
				return cached, nil
			}
		}
		log.Printf("using built-in range snapshot")
		return cloudflare.Fallback(), nil

	default:
		return cloudflare.Set{}, fmt.Errorf("unknown -ranges %q (want auto, api, cache, builtin)", source)
	}
}

func saveCache(path string, set cloudflare.Set) {
	if path == "" {
		return
	}
	if err := cloudflare.SaveFile(path, set); err != nil {
		log.Printf("warning: save range cache: %v", err)
	}
}

func readCIDRFile(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		out = append(out, strings.Fields(line)...)
	}
	return out, nil
}

func resolveHost(ctx context.Context, host, family string) ([]sampler.Candidate, error) {
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", host, err)
	}

	seen := make(map[netip.Addr]struct{}, len(addrs))
	out := make([]sampler.Candidate, 0, len(addrs))
	for _, addr := range addrs {
		addr = addr.Unmap()
		if !addr.IsValid() {
			continue
		}
		switch family {
		case "4":
			if !addr.Is4() {
				continue
			}
		case "6":
			if addr.Is4() {
				continue
			}
		}
		if _, ok := seen[addr]; ok {
			continue
		}
		seen[addr] = struct{}{}
		out = append(out, sampler.Candidate{
			Addr:   addr,
			Prefix: netip.PrefixFrom(addr, addr.BitLen()),
		})
	}

	sort.Slice(out, func(i, j int) bool {
		return out[i].Addr.Compare(out[j].Addr) < 0
	})
	if len(out) == 0 {
		return nil, fmt.Errorf("no %s addresses for %s", family, host)
	}
	return out, nil
}

func openOutput(path string) (io.Writer, func() error, error) {
	if path == "" || path == "-" {
		return os.Stdout, func() error { return nil }, nil
	}
	if dir := filepath.Dir(path); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, nil, err
		}
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, nil, err
	}
	return file, file.Close, nil
}
