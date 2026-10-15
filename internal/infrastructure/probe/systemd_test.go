package probe

import "testing"

func TestUnitDetail(t *testing.T) {
	kv := map[string]string{"Id": "myapp.service", "ActiveState": "active", "SubState": "running", "UnitFileState": "enabled",
		"FragmentPath": "/etc/systemd/system/myapp.service", "ExecStart": "{ path=/opt/app/bin ; argv[]=/opt/app/bin --db-password=hunter2 --port 80 ; ignore_errors=no ; start_time=[n/a] }",
		"Environment": "PORT=80 API_TOKEN=abc", "Restart": "no", "Type": "simple", "MainPID": "123", "MemoryCurrent": "1048576", "NRestarts": "2"}
	d := unitDetail(kv)
	if d.User != "root" || d.Origin != "custom" || d.MainPID != 123 || d.Memory != 1<<20 {
		t.Fatalf("%+v", d)
	}
	if d.ExecStart == "" || contains(d.ExecStart, "hunter2") {
		t.Fatalf("exec not parsed/redacted: %q", d.ExecStart)
	}
	if len(d.EnvKeys) != 2 || d.EnvKeys[1] != "API_TOKEN" {
		t.Fatalf("env keys %v", d.EnvKeys)
	}
	if len(d.Risks) == 0 {
		t.Fatal("want risks (root without sandbox, Restart=no)")
	}
}

func contains(s, sub string) bool { return len(sub) > 0 && len(s) >= len(sub) && (s == sub || indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
