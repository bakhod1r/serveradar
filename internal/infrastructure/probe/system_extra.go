package probe

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
)

func init() {
	register(Collector{Name: "kubernetes", Title: "Kubernetes & Clusters", Profiles: everywhere, Depends: []string{"processes"}, Collect: collectK8s})
	register(Collector{Name: "firewall", Title: "Firewall", Profiles: std, Collect: collectFirewall})
	register(Collector{Name: "security", Title: "Security Posture", Profiles: everywhere, Collect: collectSecurity})
}

func collectK8s(c Ctx) (any, error) {
	k := &inventory.Kubernetes{}
	if pl, ok := c.Prior("processes").(*inventory.ProcessList); ok {
		for _, p := range pl.All {
			for _, n := range []string{"kubelet", "kube-proxy", "kube-apiserver", "k3s", "containerd", "crio", "microk8s", "etcd"} {
				if p.Comm == n || strings.HasPrefix(p.Comm, n+"-") {
					k.Signals = appendUniq(k.Signals, "process:"+p.Comm)
				}
			}
		}
	}
	for _, f := range []string{"/etc/kubernetes", "/var/lib/kubelet", "/etc/rancher/k3s", "/var/snap/microk8s", "/var/lib/rancher/rke2"} {
		if _, err := os.Stat(f); err == nil {
			k.Signals = append(k.Signals, "path:"+f)
		}
	}
	for _, s := range k.Signals {
		switch {
		case strings.Contains(s, "k3s"):
			k.Distro = "k3s"
		case strings.Contains(s, "microk8s"):
			k.Distro = "microk8s"
		case strings.Contains(s, "rke2"):
			k.Distro = "rke2"
		case k.Distro == "" && strings.Contains(s, "kubelet"):
			k.Distro = "kubernetes (kubeadm/other)"
		}
	}
	// context name only; no cluster API calls without explicit opt-in (deep profile)
	if out, err := execx.Run(c, 3*time.Second, "kubectl", "config", "current-context"); err == nil {
		k.Kubectl = strings.TrimSpace(out)
	}
	if out, err := execx.Run(c, 5*time.Second, "docker", "info", "--format", "{{.Swarm.LocalNodeState}}/{{.Swarm.ControlAvailable}}"); err == nil {
		st := strings.TrimSpace(out)
		if !strings.HasPrefix(st, "inactive") {
			k.Swarm = st
		}
	}
	if len(k.Signals) == 0 && k.Kubectl == "" && k.Swarm == "" {
		return nil, ErrUnavailable("no cluster signals")
	}
	return k, nil
}

func collectFirewall(c Ctx) (any, error) {
	f := &inventory.Firewall{}
	try := func(name string, args ...string) (string, bool) {
		if !execx.Has(name) {
			return "", false
		}
		f.Backends = append(f.Backends, name)
		out, err := execx.Run(c, 8*time.Second, name, args...)
		if err != nil {
			c.Warn("%s: needs root (%v)", name, firstLine(err.Error()))
			return "", false
		}
		return out, true
	}
	if out, ok := try("ufw", "status", "verbose"); ok {
		f.UFW = firstLine(out)
		f.Rules = append(f.Rules, limit(nonEmpty(strings.Split(out, "\n")), 60)...)
	}
	if out, ok := try("nft", "list", "ruleset"); ok {
		for _, ln := range strings.Split(out, "\n") {
			ln = strings.TrimSpace(ln)
			if strings.Contains(ln, "accept") && (strings.Contains(ln, "dport") || strings.Contains(ln, "saddr")) {
				f.Rules = append(f.Rules, "nft: "+ln)
			}
		}
	}
	if out, ok := try("iptables", "-S"); ok {
		for _, ln := range strings.Split(out, "\n") {
			if strings.HasPrefix(ln, "-P") || strings.Contains(ln, "ACCEPT") && strings.Contains(ln, "--dport") {
				f.Rules = append(f.Rules, "iptables: "+ln)
			}
		}
	}
	if out, ok := try("firewall-cmd", "--list-all"); ok {
		f.Rules = append(f.Rules, nonEmpty(strings.Split(out, "\n"))...)
	}
	if out, ok := try("pfctl", "-s", "info"); ok {
		f.Rules = append(f.Rules, "pf: "+firstLine(out))
	}
	if len(f.Backends) == 0 {
		return nil, ErrUnavailable("no firewall tooling found")
	}
	f.Rules = limit(f.Rules, 200)
	return f, nil
}

func collectSecurity(c Ctx) (any, error) {
	s := &inventory.Security{SSH: map[string]string{}}
	for _, p := range []string{"/etc/ssh/sshd_config", "/private/etc/ssh/sshd_config"} {
		files := []string{p}
		if m, _ := filepath.Glob(filepath.Join(filepath.Dir(p), "sshd_config.d", "*.conf")); m != nil {
			files = append(m, files...) // drop-ins take precedence (first value wins)
		}
		for _, f := range files {
			fh, err := os.Open(f)
			if err != nil {
				continue
			}
			s.SSHConfig = p
			sc := bufio.NewScanner(fh)
			for sc.Scan() {
				x := strings.Fields(sc.Text())
				if len(x) < 2 || strings.HasPrefix(x[0], "#") {
					continue
				}
				k := strings.ToLower(x[0])
				switch k {
				case "port", "permitrootlogin", "passwordauthentication", "pubkeyauthentication", "permitemptypasswords", "listenaddress", "x11forwarding", "kbdinteractiveauthentication":
					if _, set := s.SSH[k]; !set {
						s.SSH[k] = x[1]
					}
				}
			}
			fh.Close()
		}
		if s.SSHConfig != "" {
			break
		}
	}
	for _, f := range []string{"/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/passwd",
		"/etc/mysql/debian.cnf", "/root/.ssh", "/etc/serveradar"} {
		fi, err := os.Stat(f)
		if err != nil {
			continue
		}
		perm := fi.Mode().Perm()
		loose := perm&0o002 != 0 || (f == "/etc/shadow" || f == "/etc/gshadow" || f == "/etc/mysql/debian.cnf" || f == "/root/.ssh") && perm&0o004 != 0
		if loose {
			s.Loose = append(s.Loose, f+" "+perm.String())
		}
	}
	if b, err := os.ReadFile("/etc/group"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			x := strings.Split(ln, ":")
			if len(x) == 4 && (x[0] == "sudo" || x[0] == "wheel" || x[0] == "admin" || x[0] == "docker") && x[3] != "" {
				s.Sudoers = append(s.Sudoers, x[0]+": "+x[3])
			}
		}
	}
	if b, err := os.ReadFile("/etc/passwd"); err == nil {
		for _, ln := range strings.Split(string(b), "\n") {
			x := strings.Split(ln, ":")
			if len(x) == 7 && !strings.HasSuffix(x[6], "nologin") && !strings.HasSuffix(x[6], "false") && x[6] != "" && !strings.HasSuffix(x[6], "sync") {
				s.LoginUsers = append(s.LoginUsers, x[0]+" ("+x[6]+")")
			}
		}
	}
	return s, nil
}

func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}
