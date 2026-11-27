package discovery

import (
	"context"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"time"
)

// C57.03: обратный DNS (PTR) для найденных узлов — имя узла до сбора. Только запросы к DNS-серверу collector
// (системный резолвер); к самим узлам ничего не отправляется.

// LookupAddr — функция PTR-запроса (net.Resolver.LookupAddr); подменяется в тестах.
type LookupAddr func(ctx context.Context, addr string) ([]string, error)

var dnsName = regexp.MustCompile(`^(?i)[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9_-]{0,62}))*$`)

// CleanPTR — первое пригодное имя из ответа PTR: строчными, без завершающей точки, не длиннее 253.
func CleanPTR(names []string) string {
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n != "" && len(n) <= 253 && dnsName.MatchString(n) {
			return n
		}
	}
	return ""
}

// ReverseNames запрашивает PTR для адресов: не более concurrency запросов одновременно, timeout на запрос, весь
// поиск — не дольше budget (что не успело — без имени). Нет записи или ошибка — адреса нет в ответе.
func ReverseNames(ctx context.Context, lookup LookupAddr, addrs []netip.Addr, concurrency int, timeout, budget time.Duration) map[netip.Addr]string {
	out := map[netip.Addr]string{}
	if lookup == nil || len(addrs) == 0 {
		return out
	}
	if concurrency < 1 {
		concurrency = 1
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	for _, a := range addrs {
		select {
		case <-ctx.Done():
			wg.Wait()
			return out
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(a netip.Addr) {
			defer wg.Done()
			defer func() { <-sem }()
			q, c := context.WithTimeout(ctx, timeout)
			names, err := lookup(q, a.String())
			c()
			if err != nil {
				return
			}
			if n := CleanPTR(names); n != "" {
				mu.Lock()
				out[a] = n
				mu.Unlock()
			}
		}(a)
	}
	wg.Wait()
	return out
}
