package main

import (
	"errors"
	"os"
	"testing"
	"time"
)

func TestPOSIXTimezone(t *testing.T) {
	for _, tc := range []struct {
		setting        string
		winter, summer int
	}{
		{"<+05>-5", 5 * 3600, 5 * 3600},
		{"UTC0", 0, 0},
		{"NPT-5:45", 5*3600 + 45*60, 5*3600 + 45*60},
		{"NST3:30", -3*3600 - 30*60, -3*3600 - 30*60},
		{"CET-1CEST,M3.5.0/2,M10.5.0/3", 3600, 2 * 3600},
		{"EST5EDT,M3.2.0/2,M11.1.0/2", -5 * 3600, -4 * 3600},
		{"AEST-10AEDT-11,M10.1.0,M4.1.0/3", 11 * 3600, 10 * 3600},
	} {
		t.Run(tc.setting, func(t *testing.T) {
			location, err := loadPOSIXTimezone(tc.setting)
			if err != nil {
				t.Fatal(err)
			}
			for _, year := range []int{1970, 2026, 2030} {
				for _, month := range []time.Month{time.January, time.July} {
					want := tc.winter
					if month == time.July {
						want = tc.summer
					}
					_, offset := time.Date(year, month, 15, 12, 0, 0, 0, time.UTC).In(location).Zone()
					if offset != want {
						t.Fatalf("%d/%d: offset %d, want %d", year, month, offset, want)
					}
				}
			}
		})
	}
}

func TestPOSIXTimezoneDSTTransitions(t *testing.T) {
	location, err := loadPOSIXTimezone("EST5EDT,M3.2.0/2,M11.1.0/2")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		utc                  string
		hour, minute, offset int
	}{
		{"2026-03-08T06:59:00Z", 1, 59, -5 * 3600},
		{"2026-03-08T07:00:00Z", 3, 0, -4 * 3600},
		{"2026-11-01T05:59:00Z", 1, 59, -4 * 3600},
		{"2026-11-01T06:00:00Z", 1, 0, -5 * 3600},
	} {
		instant, err := time.Parse(time.RFC3339, tc.utc)
		if err != nil {
			t.Fatal(err)
		}
		local := instant.In(location)
		_, offset := local.Zone()
		if local.Hour() != tc.hour || local.Minute() != tc.minute || offset != tc.offset {
			t.Fatalf("%s: got %s", tc.utc, local)
		}
	}
}

func TestInvalidPOSIXTimezone(t *testing.T) {
	for _, value := range []string{"", "garbage", "<+05>-bad", "EST5EDT,bad", "UTC999", "UTC0\nEST5", "UTC0\x00"} {
		if _, err := loadPOSIXTimezone(value); err == nil {
			t.Errorf("accepted %q", value)
		}
	}
}

func TestLocalTimezoneSources(t *testing.T) {
	for _, tc := range []struct {
		name, goos, env, file, source     string
		explicit, wantLocation, wantError bool
		offset                            int
	}{
		{"Windows default", "windows", "", "<+05>-5", "OS default", false, false, false, 0},
		{"Linux default", "linux", "", "", "OS default", false, false, false, 0},
		{"OpenWrt file", "linux", "", "<+05>-5\n", "/etc/TZ", false, true, false, 5 * 3600},
		{"POSIX override", "linux", "NPT-5:45", "<+05>-5", "TZ", true, true, false, 5*3600 + 45*60},
		{"UTC override", "linux", "UTC", "<+05>-5", "TZ", true, true, false, 0},
		{"Empty override", "linux", "", "<+05>-5", "TZ", true, true, false, 0},
		{"Invalid file", "linux", "", "broken", "/etc/TZ", false, false, true, 0},
		{"Invalid override", "linux", "broken", "<+05>-5", "TZ", true, false, true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			location, source, err := localTimezoneWith(tc.goos, func(string) (string, bool) { return tc.env, tc.explicit }, func(path string) ([]byte, error) {
				if path != "/etc/TZ" {
					t.Fatalf("unexpected read %s", path)
				}
				if tc.file == "" {
					return nil, os.ErrNotExist
				}
				return []byte(tc.file), nil
			})
			if source != tc.source || (err != nil) != tc.wantError || (location != nil) != tc.wantLocation {
				t.Fatalf("location=%v source=%q error=%v", location, source, err)
			}
			if location != nil {
				_, offset := time.Now().In(location).Zone()
				if offset != tc.offset {
					t.Fatalf("offset %d, want %d", offset, tc.offset)
				}
			}
		})
	}
}

func TestLocalTimezoneFileOverrideAndReadError(t *testing.T) {
	// Minimal TZif v1 UTC file, independent of installed timezone data.
	data := make([]byte, 54)
	copy(data, "TZif")
	data[39], data[43] = 1, 4
	copy(data[50:], "UTC\x00")
	location, source, err := localTimezoneWith("linux", func(string) (string, bool) { return ":/custom/zone", true }, func(path string) ([]byte, error) {
		if path != "/custom/zone" {
			t.Fatalf("unexpected read %s", path)
		}
		return data, nil
	})
	if err != nil || location == nil || source != "TZ" {
		t.Fatalf("%v %s %v", location, source, err)
	}
	_, offset := time.Now().In(location).Zone()
	if offset != 0 {
		t.Fatal(offset)
	}
	_, _, err = localTimezoneWith("linux", func(string) (string, bool) { return "", false }, func(string) ([]byte, error) { return nil, os.ErrPermission })
	if !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
}
