// Package schedule parses cron expressions: human description, next run, frequency. Pure domain logic.
package schedule

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

type Spec struct {
	min, hour, dom, mon, dow [64]bool
	domStar, dowStar         bool
	Raw                      string
	Reboot                   bool
}

var macros = map[string]string{"@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0",
	"@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *"}

var monNames = map[string]int{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
var dowNames = map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}

func Parse(expr string) (*Spec, error) {
	expr = strings.TrimSpace(expr)
	s := &Spec{Raw: expr}
	if expr == "@reboot" {
		s.Reboot = true
		return s, nil
	}
	if m, ok := macros[expr]; ok {
		expr = m
	}
	// periodic dirs from cron.{hourly,daily,...} come as "@daily" etc. handled above
	f := strings.Fields(expr)
	if len(f) != 5 {
		return nil, fmt.Errorf("expected 5 fields, got %d", len(f))
	}
	type fld struct {
		dst      *[64]bool
		lo, hi   int
		names    map[string]int
	}
	fs := []fld{{&s.min, 0, 59, nil}, {&s.hour, 0, 23, nil}, {&s.dom, 1, 31, nil}, {&s.mon, 1, 12, monNames}, {&s.dow, 0, 7, dowNames}}
	for i, x := range fs {
		if err := parseField(f[i], x.lo, x.hi, x.names, x.dst); err != nil {
			return nil, fmt.Errorf("field %d %q: %w", i+1, f[i], err)
		}
	}
	if s.dow[7] {
		s.dow[0] = true
	}
	s.domStar = f[2] == "*" || f[2] == "?"
	s.dowStar = f[4] == "*" || f[4] == "?"
	return s, nil
}

func parseField(f string, lo, hi int, names map[string]int, dst *[64]bool) error {
	for _, part := range strings.Split(f, ",") {
		step := 1
		if a, b, ok := strings.Cut(part, "/"); ok {
			n, err := strconv.Atoi(b)
			if err != nil || n <= 0 {
				return fmt.Errorf("bad step")
			}
			part, step = a, n
		}
		from, to := lo, hi
		switch {
		case part == "*" || part == "?":
		case strings.Contains(part, "-"):
			a, b, _ := strings.Cut(part, "-")
			var e1, e2 error
			from, e1 = val(a, names)
			to, e2 = val(b, names)
			if e1 != nil || e2 != nil {
				return fmt.Errorf("bad range")
			}
		default:
			v, err := val(part, names)
			if err != nil {
				return err
			}
			from, to = v, v
			if step > 1 {
				to = hi
			}
		}
		if from < lo || to > hi || from > to {
			return fmt.Errorf("out of range")
		}
		for v := from; v <= to; v += step {
			dst[v] = true
		}
	}
	return nil
}

func val(s string, names map[string]int) (int, error) {
	if names != nil {
		if v, ok := names[strings.ToLower(s)]; ok {
			return v, nil
		}
	}
	return strconv.Atoi(s)
}

func (s *Spec) match(t time.Time) bool {
	if !s.min[t.Minute()] || !s.hour[t.Hour()] || !s.mon[int(t.Month())] {
		return false
	}
	d, w := s.dom[t.Day()], s.dow[int(t.Weekday())]
	switch {
	case s.domStar && s.dowStar:
		return true
	case s.domStar:
		return w
	case s.dowStar:
		return d
	default:
		return d || w // cron semantics: either
	}
}

// Next returns the next run after t (searches up to ~1 year).
func (s *Spec) Next(t time.Time) (time.Time, bool) {
	if s.Reboot {
		return time.Time{}, false
	}
	t = t.Truncate(time.Minute).Add(time.Minute)
	for i := 0; i < 366*24*60; i++ {
		if !s.mon[int(t.Month())] {
			t = time.Date(t.Year(), t.Month()+1, 1, 0, 0, 0, 0, t.Location())
			continue
		}
		if !s.hour[t.Hour()] {
			t = t.Truncate(time.Hour).Add(time.Hour)
			continue
		}
		if s.match(t) {
			return t, true
		}
		t = t.Add(time.Minute)
	}
	return time.Time{}, false
}

// PerDay: average runs per day over the next 7 days.
func (s *Spec) PerDay(from time.Time) float64 {
	if s.Reboot {
		return 0
	}
	n, t, end := 0, from, from.Add(7*24*time.Hour)
	for n < 20000 {
		nx, ok := s.Next(t)
		if !ok || nx.After(end) {
			break
		}
		n++
		t = nx
	}
	return float64(n) / 7
}

func count(a *[64]bool, lo, hi int) (n int, list []int) {
	for i := lo; i <= hi; i++ {
		if a[i] {
			n++
			list = append(list, i)
		}
	}
	return
}

// Describe gives a short human description.
func (s *Spec) Describe() string {
	if s.Reboot {
		return "at every boot"
	}
	nm, ml := count(&s.min, 0, 59)
	nh, hl := count(&s.hour, 0, 23)
	var when string
	switch {
	case nm == 60 && nh == 24:
		when = "every minute"
	case nm == 60:
		when = "every minute during hours " + join(hl)
	case nh == 24 && nm == 1:
		when = fmt.Sprintf("hourly at :%02d", ml[0])
	case nh == 24:
		if st := stepOf(ml, 60); st > 0 {
			when = fmt.Sprintf("every %d minutes", st)
		} else {
			when = "at minutes " + join(ml) + " of every hour"
		}
	case nm == 1 && nh <= 6:
		var ts []string
		for _, h := range hl {
			ts = append(ts, fmt.Sprintf("%02d:%02d", h, ml[0]))
		}
		when = "at " + strings.Join(ts, ", ")
	default:
		if st := stepOf(hl, 24); st > 0 && nm == 1 {
			when = fmt.Sprintf("every %d hours at :%02d", st, ml[0])
		} else {
			when = fmt.Sprintf("minutes %s of hours %s", join(ml), join(hl))
		}
	}
	var days []string
	if !s.domStar {
		_, dl := count(&s.dom, 1, 31)
		days = append(days, "on day "+join(dl)+" of month")
	}
	if !s.dowStar {
		_, wl := count(&s.dow, 0, 6)
		wn := []string{"Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"}
		var ws []string
		for _, w := range wl {
			ws = append(ws, wn[w])
		}
		days = append(days, "on "+strings.Join(ws, ","))
	}
	if nmo, mo := count(&s.mon, 1, 12); nmo < 12 {
		days = append(days, "in month "+join(mo))
	}
	if len(days) == 0 {
		return when + ", every day"
	}
	return when + ", " + strings.Join(days, " or ")
}

func stepOf(l []int, span int) int {
	if len(l) < 2 || l[0] != 0 {
		return 0
	}
	st := l[1] - l[0]
	for i := 1; i < len(l); i++ {
		if l[i]-l[i-1] != st {
			return 0
		}
	}
	if span%st != 0 && len(l) != (span+st-1)/st {
		return 0
	}
	return st
}

func join(l []int) string {
	var s []string
	for _, x := range l {
		s = append(s, strconv.Itoa(x))
	}
	if len(s) > 12 {
		return strings.Join(s[:12], ",") + ",…"
	}
	return strings.Join(s, ",")
}
