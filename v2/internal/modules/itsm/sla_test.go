package itsm

import (
	"testing"
	"time"
)

func TestBusinessCalendar(t *testing.T) {
	c, err := DefaultHours.calendar()
	if err != nil {
		t.Fatal(err)
	}
	msk := c.loc
	at := func(d, h, m int) time.Time { return time.Date(2026, 11, d, h, m, 0, 0, msk) } // 16.11.2026 — понедельник
	cases := []struct {
		a, b time.Time
		want float64
	}{
		{at(16, 10, 0), at(16, 11, 30), 90},   // внутри дня
		{at(16, 8, 0), at(16, 10, 0), 60},     // до начала не считается
		{at(16, 17, 0), at(17, 10, 0), 120},   // через ночь
		{at(20, 17, 0), at(23, 10, 0), 120},   // пятница → понедельник, выходные не считаются
		{at(21, 10, 0), at(22, 18, 0), 0},     // выходные
		{at(16, 9, 0), at(23, 9, 0), 5 * 540}, // неделя
	}
	for i, tc := range cases {
		if got := c.Minutes(tc.a, tc.b); got != tc.want {
			t.Fatalf("case %d: %v want %v", i, got, tc.want)
		}
	}
	if due := c.Add(at(20, 17, 30), 60); !due.Equal(at(23, 9, 30)) {
		t.Fatal("deadline must skip the weekend", due)
	}
	if due := c.Add(at(16, 7, 0), 30); !due.Equal(at(16, 9, 30)) {
		t.Fatal("deadline before working hours starts at opening", due)
	}
	// таймер: пауза не считается, после срока — нарушение
	tr := timerRow{metric: "resolution", target: 120, started: at(16, 9, 0), paused: 30}
	if v := c.view(tr, 80, at(16, 10, 30)); v.Elapsed != 60 || v.Status != "running" || v.DueAt == nil || !v.DueAt.Equal(at(16, 11, 30)) {
		t.Fatalf("running: %+v", v)
	}
	if v := c.view(tr, 80, at(16, 11, 10)); v.Status != "warning" {
		t.Fatalf("warning: %+v", v)
	}
	if v := c.view(tr, 80, at(16, 12, 0)); v.Status != "breached" || v.DueAt != nil {
		t.Fatalf("breached: %+v", v)
	}
	ps := at(16, 10, 0)
	tr.pausedSince = &ps
	if v := c.view(tr, 80, at(17, 12, 0)); v.Status != "paused" || v.Elapsed != 30 {
		t.Fatalf("paused: %+v", v)
	}
	for _, bad := range []BusinessHours{{Timezone: "Nowhere/City", Days: []int{1}, StartMinute: 0, EndMinute: 60, WarnPercent: 80}, {Timezone: "UTC", Days: []int{1, 1}, StartMinute: 0, EndMinute: 60, WarnPercent: 80}, {Timezone: "UTC", Days: []int{8}, StartMinute: 0, EndMinute: 60, WarnPercent: 80}, {Timezone: "UTC", Days: []int{1}, StartMinute: 600, EndMinute: 600, WarnPercent: 80}} {
		if _, err := bad.calendar(); err == nil {
			t.Fatalf("invalid hours accepted: %+v", bad)
		}
	}
}
