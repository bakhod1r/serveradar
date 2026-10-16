// Package model defines the stable, versioned report schema.
package inventory

import "time"

const SchemaVersion = "1.0"

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

var SeverityOrder = map[Severity]int{Critical: 0, High: 1, Medium: 2, Low: 3, Info: 4}

type Confidence string

const (
	Confirmed Confidence = "confirmed"
	Strong    Confidence = "strong"
	Possible  Confidence = "possible"
	Unknown   Confidence = "unknown"
)

type Status string

const (
	StatusOK          Status = "ok"
	StatusPartial     Status = "partial"
	StatusUnavailable Status = "unavailable"
	StatusSkipped     Status = "skipped"
	StatusError       Status = "error"
)

type Finding struct {
	ID         string     `json:"id"`
	Title      string     `json:"title"`
	Severity   Severity   `json:"severity"`
	Component  string     `json:"component"`
	Evidence   string     `json:"evidence"`
	Confidence Confidence `json:"confidence"`
	Impact     string     `json:"impact"`
	NextStep   string     `json:"next_step"`
	Method     string     `json:"method"`
	Timestamp  time.Time  `json:"timestamp"`
}

type Relationship struct {
	Source     string     `json:"source"`
	Target     string     `json:"target"`
	Kind       string     `json:"kind"`
	Confidence Confidence `json:"confidence"`
	Evidence   string     `json:"evidence"`
}

type CollectorResult struct {
	Name       string   `json:"name"`
	Status     Status   `json:"status"`
	DurationMs int64    `json:"duration_ms"`
	Warnings   []string `json:"warnings,omitempty"`
	Error      string   `json:"error,omitempty"`
	Data       any      `json:"data,omitempty"`
}

type Privileges struct {
	User     string `json:"user"`
	UID      int    `json:"uid"`
	Root     bool   `json:"root"`
	SudoBin  bool   `json:"sudo_available"`
	Platform string `json:"platform"`
}

type Report struct {
	SchemaVersion string                      `json:"schema_version"`
	ToolVersion   string                      `json:"tool_version"`
	Hostname      string                      `json:"hostname"`
	Profile       string                      `json:"profile"`
	StartedAt     time.Time                   `json:"started_at"`
	FinishedAt    time.Time                   `json:"finished_at"`
	Privileges    Privileges                  `json:"privileges"`
	Collectors    map[string]*CollectorResult `json:"collectors"`
	Order         []string                    `json:"-"`
	Findings      []Finding                   `json:"findings"`
	Relationships []Relationship              `json:"relationships"`
	Exposure      []PortExposure              `json:"port_exposure"`
}

// ---- typed observations ----

type Mount struct {
	Device     string  `json:"device"`
	Mountpoint string  `json:"mountpoint"`
	FSType     string  `json:"fstype"`
	ReadOnly   bool    `json:"read_only"`
	TotalBytes uint64  `json:"total_bytes"`
	UsedBytes  uint64  `json:"used_bytes"`
	UsedPct    float64 `json:"used_pct"`
	InodesPct  float64 `json:"inodes_used_pct"`
}

type Host struct {
	Hostname       string     `json:"hostname"`
	OS             string     `json:"os"`
	Distro         string     `json:"distro"`
	Kernel         string     `json:"kernel"`
	Arch           string     `json:"arch"`
	MachineIDHash  string     `json:"machine_id_hash,omitempty"`
	BootTime       time.Time  `json:"boot_time"`
	UptimeSec      int64      `json:"uptime_sec"`
	Timezone       string     `json:"timezone"`
	Virtualization string     `json:"virtualization,omitempty"`
	CPUModel       string     `json:"cpu_model"`
	CPUs           int        `json:"logical_cpus"`
	Load           [3]float64 `json:"load_avg"`
	MemTotal       uint64     `json:"mem_total"`
	MemAvailable   uint64     `json:"mem_available"`
	MemCached      uint64     `json:"mem_cached"`
	SwapTotal      uint64     `json:"swap_total"`
	SwapFree       uint64     `json:"swap_free"`
	Mounts         []Mount    `json:"mounts"`
	RebootRequired bool       `json:"reboot_required"`
}

type Process struct {
	PID     int     `json:"pid"`
	PPID    int     `json:"ppid"`
	User    string  `json:"user"`
	CPU     float64 `json:"cpu_pct"`
	MemRSS  uint64  `json:"rss_bytes"`
	Start   string  `json:"start"`
	Comm    string  `json:"comm"`
	Cmdline string  `json:"cmdline"`
}

type Socket struct {
	Proto   string `json:"proto"`
	Address string `json:"address"`
	Port    int    `json:"port"`
	PID     int    `json:"pid,omitempty"`
	Process string `json:"process,omitempty"`
	Public  bool   `json:"wildcard_bind"`
	Owner   string `json:"owner,omitempty"` // service/container correlation
}

type Interface struct {
	Name  string   `json:"name"`
	MAC   string   `json:"mac,omitempty"`
	MTU   int      `json:"mtu"`
	Up    bool     `json:"up"`
	Addrs []string `json:"addrs"`
}

type Network struct {
	Interfaces  []Interface    `json:"interfaces"`
	Routes      []string       `json:"routes"`
	Nameservers []string       `json:"nameservers"`
	ConnStates  map[string]int `json:"conn_states,omitempty"`
	IPForward   string         `json:"ip_forward,omitempty"`
}

type Unit struct {
	Name    string `json:"name"`
	Load    string `json:"load"`
	Active  string `json:"active"`
	Sub     string `json:"sub"`
	Enabled string `json:"enabled,omitempty"`
	Desc    string `json:"description"`
}

type Container struct {
	ID          string            `json:"id"`
	Name        string            `json:"name"`
	Image       string            `json:"image"`
	State       string            `json:"state"`
	Status      string            `json:"status"`
	Health      string            `json:"health,omitempty"`
	Restart     string            `json:"restart_policy,omitempty"`
	RestartCnt  int               `json:"restart_count"`
	Created     string            `json:"created"`
	Ports       []string          `json:"ports"`
	Privileged  bool              `json:"privileged"`
	HostNet     bool              `json:"host_network"`
	HostPID     bool              `json:"host_pid"`
	CapAdd      []string          `json:"cap_add,omitempty"`
	Mounts      []string          `json:"mounts,omitempty"`
	SocketMount bool              `json:"docker_socket_mount"`
	Compose     string            `json:"compose_project,omitempty"`
	ComposeDir  string            `json:"compose_dir,omitempty"`
	EnvCount    int               `json:"env_var_count"`
	Env         []string          `json:"env,omitempty"`
	Networks    map[string]string `json:"networks,omitempty"` // network -> ip
	Cmd         string            `json:"cmd,omitempty"`
}

type Docker struct {
	Version         string              `json:"version"`
	Rootless        bool                `json:"rootless"`
	Containers      []Container         `json:"containers"`
	Images          []map[string]string `json:"images"`
	Dangling        int                 `json:"dangling_images"`
	Networks        []map[string]string `json:"networks"`
	Volumes         []map[string]string `json:"volumes"`
	OrphanVols      []string            `json:"unattached_volumes"`
	Stats           []map[string]string `json:"container_stats,omitempty"`
	ComposeProjects map[string]string   `json:"compose_projects,omitempty"`
}

type Vhost struct {
	File        string   `json:"file"`
	ServerNames []string `json:"server_names"`
	Listens     []string `json:"listens"`
	ProxyPass   []string `json:"proxy_pass"`
	Roots       []string `json:"roots"`
	SSLCert     string   `json:"ssl_certificate,omitempty"`
	DefaultSrv  bool     `json:"default_server"`
	Redirect    bool     `json:"https_redirect"`
	StubStatus  bool     `json:"stub_status"`
}

type Nginx struct {
	Version   string              `json:"version"`
	Running   bool                `json:"running"`
	Source    string              `json:"source"` // nginx -T | files
	Heuristic bool                `json:"heuristic_parse"`
	Vhosts    []Vhost             `json:"vhosts"`
	Upstreams map[string][]string `json:"upstreams"`
}

type Cert struct {
	Path     string    `json:"path"`
	Subject  string    `json:"subject"`
	Issuer   string    `json:"issuer"`
	SANs     []string  `json:"sans"`
	NotAfter time.Time `json:"not_after"`
	DaysLeft int       `json:"days_left"`
	UsedBy   []string  `json:"used_by,omitempty"`
}

type Project struct {
	Path      string   `json:"path"`
	Markers   []string `json:"markers"`
	Git       *Git     `json:"git,omitempty"`
	EnvFiles  []string `json:"env_files,omitempty"`
	EnvLoose  []string `json:"env_world_readable,omitempty"`
	Manifests []string `json:"deploy_manifests,omitempty"`
}

type Git struct {
	Branch string `json:"branch"`
	Commit string `json:"commit"`
	Dirty  bool   `json:"dirty"`
	Remote string `json:"remote,omitempty"`
}

type Service struct {
	Kind      string   `json:"kind"`
	Source    []string `json:"detected_by"`
	PIDs      []int    `json:"pids,omitempty"`
	Ports     []int    `json:"ports,omitempty"`
	Configs   []string `json:"config_paths,omitempty"`
	Version   string   `json:"version,omitempty"`
	Cluster   string   `json:"cluster_hint,omitempty"`
	Container string   `json:"container,omitempty"`
}
