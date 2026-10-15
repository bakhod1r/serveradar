package probe

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/bakhod1r/serveradar/internal/domain/inventory"
	"github.com/bakhod1r/serveradar/internal/infrastructure/execx"
	"github.com/bakhod1r/serveradar/internal/infrastructure/redact"
)

func init() {
	register(Collector{Name: "docker", Title: "Docker", Profiles: everywhere, Collect: collectDocker})
}

type inspectC struct {
	ID      string `json:"Id"`
	Name    string
	Created string
	Config  struct {
		Image       string
		Env         []string
		Cmd         []string
		Labels      map[string]string
		Healthcheck *struct{ Test []string }
	}
	State struct {
		Status string
		Health *struct{ Status string }
	}
	RestartCount int
	HostConfig   struct {
		Privileged    bool
		NetworkMode   string
		PidMode       string
		CapAdd        []string
		RestartPolicy struct{ Name string }
	}
	Mounts []struct {
		Type, Source, Destination, Name string
		RW                              bool
	}
	NetworkSettings struct {
		Ports    map[string][]struct{ HostIp, HostPort string }
		Networks map[string]struct{ IPAddress string }
	}
}

func collectDocker(c Ctx) (any, error) {
	if !execx.Has("docker") {
		return nil, ErrUnavailable("docker CLI not installed")
	}
	ver, err := execx.Run(c, 8*time.Second, "docker", "version", "--format", "{{.Server.Version}}")
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			return nil, fmt.Errorf("docker socket permission denied (add user to docker group or use sudo)")
		}
		return nil, ErrUnavailable("docker daemon not reachable")
	}
	d := &inventory.Docker{Version: strings.TrimSpace(ver), ComposeProjects: map[string]string{}}
	if so, err := execx.Run(c, 8*time.Second, "docker", "info", "--format", "{{json .SecurityOptions}}"); err == nil {
		d.Rootless = strings.Contains(so, "rootless")
	}

	ids, _ := execx.Run(c, 10*time.Second, "docker", "ps", "-aq", "--no-trunc")
	idl := nonEmpty(strings.Split(ids, "\n"))
	attachedVols := map[string]bool{}
	if len(idl) > 0 {
		out, err := execx.Run(c, 20*time.Second, "docker", append([]string{"inspect"}, idl...)...)
		if err != nil && out == "" {
			c.Warn("docker inspect: %v", err)
		}
		var ins []inspectC
		_ = json.Unmarshal([]byte(out), &ins)
		for _, x := range ins {
			ct := inventory.Container{
				ID: x.ID[:12], Name: strings.TrimPrefix(x.Name, "/"), Image: x.Config.Image, State: x.State.Status,
				Restart: x.HostConfig.RestartPolicy.Name, RestartCnt: x.RestartCount, Created: x.Created,
				Privileged: x.HostConfig.Privileged, HostNet: x.HostConfig.NetworkMode == "host",
				HostPID: x.HostConfig.PidMode == "host", CapAdd: x.HostConfig.CapAdd, EnvCount: len(x.Config.Env),
				Compose: x.Config.Labels["com.docker.compose.project"], ComposeDir: x.Config.Labels["com.docker.compose.project.working_dir"],
			}
			if x.State.Health != nil {
				ct.Health = x.State.Health.Status
			} else if x.Config.Healthcheck == nil {
				ct.Health = "none"
			}
			for cport, binds := range x.NetworkSettings.Ports {
				for _, b := range binds {
					ct.Ports = append(ct.Ports, fmt.Sprintf("%s:%s->%s", orStar(b.HostIp), b.HostPort, cport))
				}
			}
			for _, m := range x.Mounts {
				src := m.Source
				if m.Type == "volume" {
					src = "vol:" + m.Name
					attachedVols[m.Name] = true
				}
				mode := "ro"
				if m.RW {
					mode = "rw"
				}
				ct.Mounts = append(ct.Mounts, src+":"+m.Destination+":"+mode)
				if strings.HasSuffix(m.Source, "docker.sock") {
					ct.SocketMount = true
				}
			}
			ct.Networks = map[string]string{}
			for name, n := range x.NetworkSettings.Networks {
				ct.Networks[name] = n.IPAddress
			}
			ct.Cmd = redact.Text(truncate(strings.Join(x.Config.Cmd, " "), 200))
			for _, e := range x.Config.Env {
				k, v, _ := strings.Cut(e, "=")
				switch {
				case !c.Policy().ShowEnv:
					ct.Env = append(ct.Env, k)
				case sensitiveKey(k):
					ct.Env = append(ct.Env, k+"="+redact.Mask)
				default:
					ct.Env = append(ct.Env, redact.Text(k+"="+truncate(v, 200)))
				}
			}
			if ct.Compose != "" {
				d.ComposeProjects[ct.Compose] = ct.ComposeDir
			}
			d.Containers = append(d.Containers, ct)
		}
	}

	d.Images = jsonLines(c, "docker", "images", "-a", "--format", "{{json .}}")
	for _, im := range d.Images {
		if im["Repository"] == "<none>" && im["Tag"] == "<none>" {
			d.Dangling++
		}
	}
	d.Networks = jsonLines(c, "docker", "network", "ls", "--format", "{{json .}}")
	for i, n := range d.Networks {
		out, err := execx.Run(c, 5*time.Second, "docker", "network", "inspect", "--format",
			"{{range .IPAM.Config}}{{.Subnet}} gw={{.Gateway}} {{end}}|{{len .Containers}}", n["ID"])
		if err == nil {
			a, b, _ := strings.Cut(strings.TrimSpace(out), "|")
			d.Networks[i]["Subnets"], d.Networks[i]["AttachedContainers"] = strings.TrimSpace(a), b
		}
	}
	d.Volumes = jsonLines(c, "docker", "volume", "ls", "--format", "{{json .}}")
	for _, v := range d.Volumes {
		if !attachedVols[v["Name"]] {
			d.OrphanVols = append(d.OrphanVols, v["Name"])
		}
	}
	d.Stats = jsonLines(c, "docker", "stats", "--no-stream", "--format", "{{json .}}")
	return d, nil
}

func jsonLines(c Ctx, name string, args ...string) []map[string]string {
	out, err := execx.Run(c, 20*time.Second, name, args...)
	if err != nil && out == "" {
		c.Warn("%s %s: %v", name, strings.Join(args[:min(2, len(args))], " "), err)
		return nil
	}
	var res []map[string]string
	for _, ln := range nonEmpty(strings.Split(out, "\n")) {
		raw := map[string]any{}
		if json.Unmarshal([]byte(ln), &raw) != nil {
			continue
		}
		m := map[string]string{}
		for k, v := range raw {
			m[k] = fmt.Sprint(v)
		}
		res = append(res, m)
	}
	return res
}

var sensitiveRe = regexp.MustCompile(`(?i)pass|secret|token|key|auth|cred|cookie|session|salt|private|dsn|_url$|uri$|conn`)

func sensitiveKey(k string) bool { return sensitiveRe.MatchString(k) }

func orStar(s string) string {
	if s == "" {
		return "0.0.0.0"
	}
	return s
}
