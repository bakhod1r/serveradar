package probe

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/redact"
)

func TestParseNginx(t *testing.T) {
	conf := `
upstream app { server 127.0.0.1:8080 weight=2; server 127.0.0.1:8081; }
server {
  listen 80 default_server;
  server_name example.com www.example.com;
  return 301 https://$host$request_uri;
}
server {
  listen 443 ssl; # comment
  server_name "example.com";
  ssl_certificate /etc/letsencrypt/live/example.com/fullchain.pem;
  location / { proxy_pass http://app; }
  location /status { stub_status; }
}`
	n := &inventory.Nginx{Upstreams: map[string][]string{}}
	parseNginx(n, "test.conf", conf)
	if len(n.Vhosts) != 2 {
		t.Fatalf("vhosts=%d", len(n.Vhosts))
	}
	if !n.Vhosts[0].Redirect || !n.Vhosts[0].DefaultSrv {
		t.Errorf("redirect/default not detected: %+v", n.Vhosts[0])
	}
	v := n.Vhosts[1]
	if v.SSLCert == "" || len(v.ProxyPass) != 1 || !v.StubStatus {
		t.Errorf("bad vhost: %+v", v)
	}
	if len(n.Upstreams["app"]) != 2 {
		t.Errorf("upstreams: %v", n.Upstreams)
	}
}

func TestMongoConf(t *testing.T) {
	p := filepath.Join(t.TempDir(), "mongod.conf")
	os.WriteFile(p, []byte("net:\n  port: 27017\n  bindIp: 0.0.0.0\nreplication:\n  replSetName: rs0\n# security:\n"), 0o600)
	m := mongoConf(p)
	if m.Port != 27017 || m.BindIP != "0.0.0.0" || m.ReplSet != "rs0" || !strings.HasPrefix(m.Authorization, "disabled") {
		t.Fatalf("%+v", m)
	}
}

func TestCronParse(t *testing.T) {
	cr := &inventory.Cron{}
	parseCronText(cr, "/etc/crontab", "", "SHELL=/bin/sh\n17 * * * * root cd / && run-parts --report /etc/cron.hourly\n@reboot www /srv/app --password=hunter2\n", true)
	if len(cr.Jobs) != 2 {
		t.Fatalf("jobs=%+v", cr.Jobs)
	}
	if cr.Jobs[0].User != "root" || cr.Jobs[0].Schedule != "17 * * * *" {
		t.Errorf("job0 %+v", cr.Jobs[0])
	}
	if strings.Contains(cr.Jobs[1].Command, "hunter2") {
		t.Errorf("secret leaked: %s", cr.Jobs[1].Command)
	}
}

func TestRedact(t *testing.T) {
	cases := map[string]string{
		"postgres://user:pw@db:5432/x":     "hunter",
		"--password=hunter2 --port 1":       "hunter2",
		"Authorization: Bearer abcdefghijk": "abcdefghijk",
		"token ghp_abcdefghijklmnopqrstuvwxyz12": "ghp_",
	}
	for in, secret := range cases {
		if out := redact.Text(in); strings.Contains(out, secret) || strings.Contains(out, "pw@") {
			t.Errorf("%q -> %q", in, out)
		}
	}
}
