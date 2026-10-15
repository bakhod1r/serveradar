package schedule

import (
	"testing"
	"time"
)

func TestDescribeAndNext(t *testing.T) {
	base := time.Date(2026, 10, 15, 10, 7, 0, 0, time.UTC) // Thursday
	cases := []struct {
		expr, desc string
		next       time.Time
		perDay     float64
	}{
		{"* * * * *", "every minute, every day", base.Add(time.Minute), 1440},
		{"*/15 * * * *", "every 15 minutes, every day", time.Date(2026, 10, 15, 10, 15, 0, 0, time.UTC), 96},
		{"30 2 * * *", "at 02:30, every day", time.Date(2026, 10, 16, 2, 30, 0, 0, time.UTC), 1},
		{"0 3 * * 0", "at 03:00, on Sun", time.Date(2026, 10, 18, 3, 0, 0, 0, time.UTC), 1.0 / 7},
		{"@hourly", "hourly at :00", time.Date(2026, 10, 15, 11, 0, 0, 0, time.UTC), 24},
	}
	for _, c := range cases {
		s, err := Parse(c.expr)
		if err != nil {
			t.Fatalf("%s: %v", c.expr, err)
		}
		if d := s.Describe(); d[:len(c.desc)] != c.desc {
			t.Errorf("%s: describe %q want prefix %q", c.expr, d, c.desc)
		}
		if n, _ := s.Next(base); !n.Equal(c.next) {
			t.Errorf("%s: next %v want %v", c.expr, n, c.next)
		}
		if p := s.PerDay(base); p < c.perDay-0.01 || p > c.perDay+0.01 {
			t.Errorf("%s: perDay %v want %v", c.expr, p, c.perDay)
		}
	}
	if _, err := Parse("61 * * * *"); err == nil {
		t.Error("want error for minute 61")
	}
}
