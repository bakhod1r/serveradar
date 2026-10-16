package updater

import "testing"

func TestNewer(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{{"v0.1.0", "v0.1.1", true}, {"v0.1.1", "v0.1.1", false}, {"v0.2.0", "v0.1.9", false}, {"dev", "v0.1.0", true}, {"v1.0.0", "v1.0.0-rc1", false}, {"v0.9.9", "v1.0.0", true}}
	for _, c := range cases {
		if got := Newer(c.a, c.b); got != c.want {
			t.Errorf("Newer(%s,%s)=%v", c.a, c.b, got)
		}
	}
}
