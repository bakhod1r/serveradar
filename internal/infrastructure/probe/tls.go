package probe

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
)

func init() {
	register(Collector{Name: "tls", Title: "TLS Certificates", Profiles: std, Depends: []string{"nginx"}, Collect: collectTLS})
}

func collectTLS(c Ctx) (any, error) {
	t := &inventory.TLS{}
	paths := map[string][]string{} // cert path -> used by
	if n, ok := c.Prior("nginx").(*inventory.Nginx); ok {
		for _, v := range n.Vhosts {
			if v.SSLCert != "" {
				paths[v.SSLCert] = append(paths[v.SSLCert], strings.Join(v.ServerNames, " "))
			}
		}
	}
	for _, d := range c.Policy().CertDirs {
		m, _ := filepath.Glob(filepath.Join(d, "*", "fullchain.pem"))
		for _, p := range m {
			if _, ok := paths[p]; !ok {
				paths[p] = nil
			}
		}
	}
	for p, used := range paths {
		b, err := os.ReadFile(p) // public cert only; never reads private keys
		if err != nil {
			c.Warn("cert %s: %v", p, err)
			continue
		}
		blk, _ := pem.Decode(b)
		if blk == nil {
			c.Warn("cert %s: not PEM", p)
			continue
		}
		x, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			c.Warn("cert %s: %v", p, err)
			continue
		}
		t.Certs = append(t.Certs, inventory.Cert{
			Path: p, Subject: x.Subject.CommonName, Issuer: x.Issuer.CommonName, SANs: x.DNSNames,
			NotAfter: x.NotAfter, DaysLeft: int(time.Until(x.NotAfter).Hours() / 24), UsedBy: used,
		})
	}
	sortBy(t.Certs, func(a, b inventory.Cert) bool { return a.DaysLeft < b.DaysLeft })
	if execx.Has("certbot") {
		t.Renewal = append(t.Renewal, "certbot")
	}
	for _, f := range []string{"/lib/systemd/system/certbot.timer", "/etc/systemd/system/certbot.timer", "/etc/cron.d/certbot"} {
		if _, err := os.Stat(f); err == nil {
			t.Renewal = append(t.Renewal, f)
		}
	}
	if h, _ := os.UserHomeDir(); h != "" {
		if _, err := os.Stat(filepath.Join(h, ".acme.sh")); err == nil {
			t.Renewal = append(t.Renewal, "acme.sh")
		}
	}
	return t, nil
}
