package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPassiveClockConfig(t *testing.T) {
	for _, clock := range []string{"03:00", "00:00", "23:59", "", "24:00", "3:00", "bad"} {
		cfg, err := loadConfig(writeModeTestFile(t, "mode=passive\npassive_domains_file=list\ndirect_dns=1.1.1.1\npassive_resolve_time="+clock+"\n"))
		valid := clock == "03:00" || clock == "00:00" || clock == "23:59" || clock == ""
		if valid && (err != nil || cfg.PassiveResolveTime != clock) {
			t.Fatalf("%q: %v", clock, err)
		}
		if !valid && err == nil {
			t.Fatalf("accepted %q", clock)
		}
	}
}
func TestPassiveNextClock(t *testing.T) {
	for _, hour := range []int{2, 3, 4} {
		now := time.Date(2026, 10, 4, hour, 0, 0, 0, time.FixedZone("local", 3*3600))
		next := nextPassiveResolveTime(now, "03:00")
		day := 4
		if hour >= 3 {
			day = 5
		}
		if next.Day() != day || next.Hour() != 3 || next.Location() != now.Location() {
			t.Fatal(next)
		}
	}
}
func TestPassiveCleanupAndRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "reachable.ips")
	appendUniqueLine(path, "1.1.1.1", writtenReachableIPs)
	if err := os.Mkdir(filepath.Join(dir, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := clearPassiveOutputDirectory(dir); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("cleanup: %v %v", entries, err)
	}
	appendUniqueLine(path, "1.1.1.1", writtenReachableIPs)
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "1.1.1.1\n" {
		t.Fatalf("rewrite: %q %v", data, err)
	}
}
func TestPassiveClockWaitAndCleanupOrder(t *testing.T) {
	cfg := Config{PassiveResolveTime: "03:00", PassiveResolveParallel: 1, PassiveResolveInterval: time.Hour}
	waits, cleaned, resolved := 0, false, false
	err := runPassiveWithCleanup(context.Background(), cfg, func(string) ([]string, error) { return []string{"example.com"}, nil }, func(context.Context, string, Config) {
		if !cleaned || waits != 1 {
			t.Fatal("resolved before wait or cleanup")
		}
		resolved = true
	}, func(context.Context, time.Duration) bool { waits++; return waits == 1 }, func() error { cleaned = true; return nil })
	if err != nil || !resolved || waits != 2 {
		t.Fatalf("%v %v %d", err, resolved, waits)
	}
}

func TestPassiveDeadlineClockCorrections(t *testing.T) {
	for _, tc := range []struct {
		name  string
		jump  time.Duration
		waits int
	}{
		{"forward", 2 * time.Hour, 1},
		{"backward", -time.Minute, 8},
		{"unchanged", 0, 6},
	} {
		t.Run(tc.name, func(t *testing.T) {
			current := time.Date(2026, 10, 10, 0, 0, 0, 0, time.UTC)
			deadline := current.Add(3 * time.Minute)
			waits := 0
			ok := waitPassiveDeadline(context.Background(), deadline, func() time.Time { return current }, func(_ context.Context, pause time.Duration) bool {
				if pause <= 0 || pause > 30*time.Second {
					t.Fatalf("pause %s", pause)
				}
				waits++
				current = current.Add(pause)
				if waits == 1 {
					current = current.Add(tc.jump)
				}
				if waits > 20 {
					t.Fatal("did not reach deadline")
				}
				return true
			})
			if !ok || waits != tc.waits || current.Before(deadline) {
				t.Fatalf("ok=%t waits=%d time=%s", ok, waits, current)
			}
		})
	}
}

func TestPassiveDeadlineCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	now := time.Now()
	ok := waitPassiveDeadline(ctx, now.Add(time.Hour), func() time.Time { return now }, func(context.Context, time.Duration) bool { cancel(); return false })
	if ok {
		t.Fatal("continued after cancellation")
	}
	if waitPassiveDeadline(ctx, now.Add(-time.Hour), func() time.Time { return now }, func(context.Context, time.Duration) bool { t.Fatal("waited after cancellation"); return true }) {
		t.Fatal("accepted canceled overdue deadline")
	}
}

func TestPassiveScheduleNoRepeatedCalendarDay(t *testing.T) {
	for _, correction := range []string{"backward during pass", "forward across days"} {
		t.Run(correction, func(t *testing.T) {
			location := time.FixedZone("router", 5*3600)
			current := time.Date(2026, 10, 10, 2, 0, 0, 0, location)
			waits, passes := 0, 0
			cfg := Config{PassiveResolveTime: "03:00", PassiveResolveParallel: 1, PassiveResolveInterval: 168 * time.Hour}
			noop := func(context.Context) error { return nil }
			err := runPassiveWithClock(context.Background(), cfg, func(string) ([]string, error) { return []string{"example.com"}, nil }, func(context.Context, string, Config) {
				passes++
				if correction == "backward during pass" {
					current = time.Date(2026, 10, 9, 1, 0, 0, 0, location)
				}
			}, func(_ context.Context, delay time.Duration) bool {
				waits++
				if waits == 1 {
					if delay != time.Hour {
						t.Fatalf("initial delay %s", delay)
					}
					if correction == "forward across days" {
						current = time.Date(2026, 10, 13, 1, 0, 0, 0, location)
					} else {
						current = current.Add(delay)
					}
					return true
				}
				want := time.Date(2026, 10, 11, 3, 0, 0, 0, location)
				if correction == "forward across days" {
					want = time.Date(2026, 10, 14, 3, 0, 0, 0, location)
				}
				if got := current.Add(delay); !got.Equal(want) {
					t.Fatalf("next pass %s, want %s", got, want)
				}
				return false
			}, func() error { return nil }, noop, noop, func() time.Time { return current }, nil)
			if err != nil || passes != 1 || waits != 2 {
				t.Fatalf("err=%v passes=%d waits=%d", err, passes, waits)
			}
		})
	}
}

func TestPassiveScheduleUsesAbsoluteDeadlineAfterClockJump(t *testing.T) {
	current := time.Date(2026, 10, 10, 2, 59, 0, 0, time.UTC)
	deadline := current.Add(time.Minute)
	passes, waits := 0, 0
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	noop := func(context.Context) error { return nil }
	err := runPassiveWithClock(ctx, Config{PassiveResolveTime: "03:00", PassiveResolveParallel: 1},
		func(string) ([]string, error) { return []string{"example.com"}, nil },
		func(context.Context, string, Config) {
			passes++
			if waits != 0 || current.Before(deadline) {
				t.Error("pass waited after overdue clock correction")
			}
		},
		func(context.Context, time.Duration) bool {
			t.Fatal("used interval wait for daily schedule")
			return false
		},
		func() error { return nil }, noop, noop, func() time.Time { return current },
		func(ctx context.Context, target time.Time) bool {
			if passes == 1 {
				if want := time.Date(2026, 10, 14, 3, 0, 0, 0, time.UTC); !target.Equal(want) {
					t.Errorf("next pass %s, want %s", target, want)
				}
				cancel()
				return false
			}
			if !target.Equal(deadline) {
				t.Errorf("deadline changed: %s", target)
			}
			// NTP advances the wall clock between computing and waiting for a deadline.
			current = time.Date(2026, 10, 13, 1, 0, 0, 0, time.UTC)
			return waitPassiveDeadline(ctx, target, func() time.Time { return current }, func(context.Context, time.Duration) bool { waits++; return false })
		})
	if err != nil || passes != 1 || waits != 0 {
		t.Fatalf("err=%v passes=%d waits=%d", err, passes, waits)
	}
}

func TestPassiveRouterMidnightAndDST(t *testing.T) {
	location, err := loadPOSIXTimezone("<+05>-5")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 10, 9, 18, 0, 0, 0, time.UTC).In(location)
	next := nextPassiveResolveTime(now, "00:00")
	want := time.Date(2026, 10, 9, 19, 0, 0, 0, time.UTC)
	if !next.Equal(want) || next.Day() != 10 || next.Hour() != 0 {
		t.Fatalf("router midnight %s, want %s", next, want)
	}
	location, err = loadPOSIXTimezone("EST5EDT,M3.2.0/2,M11.1.0/2")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		month   time.Month
		day     int
		elapsed time.Duration
	}{
		{time.March, 7, 23 * time.Hour},
		{time.October, 31, 25 * time.Hour},
	} {
		now := time.Date(2026, tc.month, tc.day, 3, 0, 0, 0, location)
		next := nextPassiveResolveTime(now, "03:00")
		if next.Hour() != 3 || next.Sub(now) != tc.elapsed {
			t.Fatalf("DST daily deadline %s (elapsed %s), want %s", next, next.Sub(now), tc.elapsed)
		}
	}
}
