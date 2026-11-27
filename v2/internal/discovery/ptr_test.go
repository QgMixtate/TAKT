package discovery

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestCleanPTR(t *testing.T) {
	cases := map[string][]string{
		"dc01.awm.local":  {"DC01.AWM.local."},
		"esx-01.lab":      {"bad name!", "esx-01.lab."},
		"":                {"", "-", "a b.c"},
		"host_1.corp.int": {"host_1.corp.int"},
	}
	for want, in := range cases {
		if got := CleanPTR(in); got != want {
			t.Fatalf("%v: %q, want %q", in, got, want)
		}
	}
}

func TestReverseNamesBoundedAndBudgeted(t *testing.T) {
	addrs := []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.2"), netip.MustParseAddr("10.0.0.3"), netip.MustParseAddr("10.0.0.4")}
	var inflight, peak atomic.Int32
	lookup := func(ctx context.Context, addr string) ([]string, error) {
		n := inflight.Add(1)
		defer inflight.Add(-1)
		for p := peak.Load(); n > p && !peak.CompareAndSwap(p, n); p = peak.Load() {
		}
		time.Sleep(10 * time.Millisecond)
		switch addr {
		case "10.0.0.1":
			return []string{"one.lab."}, nil
		case "10.0.0.2":
			return nil, errors.New("no such host")
		case "10.0.0.3":
			<-ctx.Done() // зависший DNS — обрывается таймаутом запроса
			return nil, ctx.Err()
		}
		return []string{"four.lab"}, nil
	}
	got := ReverseNames(context.Background(), lookup, addrs, 2, 50*time.Millisecond, 5*time.Second)
	if len(got) != 2 || got[addrs[0]] != "one.lab" || got[addrs[3]] != "four.lab" {
		t.Fatalf("names %v", got)
	}
	if peak.Load() > 2 {
		t.Fatalf("concurrency %d > 2", peak.Load())
	}
	// общий предел: всё, что не успело, — без имени, без ожидания
	slow := func(ctx context.Context, addr string) ([]string, error) { <-ctx.Done(); return nil, ctx.Err() }
	start := time.Now()
	if got = ReverseNames(context.Background(), slow, addrs, 1, time.Hour, 100*time.Millisecond); len(got) != 0 || time.Since(start) > 2*time.Second {
		t.Fatalf("budget not honoured: %v %s", got, time.Since(start))
	}
}
