package inventory

// Aggregate observation types produced by probes. Domain-owned so findings/topology can reason on them.

type ProcessList struct {
	Total int       `json:"total"`
	All   []Process `json:"processes"`
}

type Usage struct {
	Key    string  `json:"key"`
	Count  int     `json:"count"`
	CPU    float64 `json:"cpu_pct"`
	RSS    uint64  `json:"rss_bytes"`
	MemPct float64 `json:"mem_pct"`
	ReadB  uint64  `json:"io_read_bytes,omitempty"`
	WriteB uint64  `json:"io_write_bytes,omitempty"`
}

type DirUsage struct {
	Path  string `json:"path"`
	Bytes uint64 `json:"bytes"`
}

type Resources struct {
	CPUs     int        `json:"logical_cpus"`
	MemTotal uint64     `json:"mem_total"`
	TopCPU   []Usage    `json:"top_cpu_processes"`
	TopMem   []Usage    `json:"top_mem_processes"`
	TopIO    []Usage    `json:"top_io_processes,omitempty"`
	ByApp    []Usage    `json:"by_application"`
	ByUser   []Usage    `json:"by_user"`
	ByUnit   []Usage    `json:"by_systemd_unit,omitempty"`
	BigDirs  []DirUsage `json:"largest_directories,omitempty"`
	IONote   string     `json:"io_note,omitempty"`
}

type Peer struct {
	Address string `json:"address"`
	Count   int    `json:"connections"`
	Ports   []int  `json:"local_ports"`
}

type Ports struct {
	Sockets []Socket `json:"listening"`
	Method  string   `json:"method"`
	// IP lists
	LocalIPs  []string `json:"local_ips"`
	Peers     []Peer   `json:"established_peers"`
	PeerNote  string   `json:"peer_note,omitempty"`
}

type UnitMem struct {
	Unit     string `json:"unit"`
	MemBytes uint64 `json:"memory_bytes"`
	CPUNsec  uint64 `json:"cpu_usage_nsec"`
	Restarts int    `json:"restarts"`
}

type Systemd struct {
	Units           []Unit    `json:"services"`
	Failed          []string  `json:"failed"`
	EnabledInactive []string  `json:"enabled_but_inactive"`
	Timers          []string  `json:"timers"`
	Usage           []UnitMem `json:"service_resource_usage"`
	Details         []ServiceUnit `json:"service_details"`
	Sockets         []string      `json:"socket_units,omitempty"`
	Mounts          []string      `json:"mount_units,omitempty"`
	Counts          map[string]int `json:"counts"`
}

type CronJob struct {
	Source   string `json:"source"`
	User     string `json:"user"`
	Schedule string `json:"schedule"`
	Command  string `json:"command"` // redacted
	Description string   `json:"description,omitempty"`
	NextRun     string   `json:"next_run,omitempty"`
	PerDay      float64  `json:"runs_per_day"`
	Script      string   `json:"script,omitempty"`
	Risks       []string `json:"risks,omitempty"`
}

type Cron struct {
	Jobs        []CronJob `json:"jobs"`
	Unreadable  []string  `json:"unreadable,omitempty"`
	LaunchAgents []string `json:"launchd_jobs,omitempty"`
	Supervisors []string  `json:"process_supervisors,omitempty"`
	Timers      []Timer   `json:"systemd_timers,omitempty"`
	Summary     []string  `json:"summary"`
}

type Kubernetes struct {
	Signals []string `json:"signals"`
	Distro  string   `json:"distribution,omitempty"`
	Kubectl string   `json:"kubectl_context,omitempty"`
	Swarm   string   `json:"swarm_state,omitempty"`
}

type TLS struct {
	Certs []Cert `json:"certificates"`
	Renewal []string `json:"renewal_tooling"`
}

type Projects struct {
	Items []Project `json:"projects"`
	Roots []string  `json:"searched_roots"`
}

// MongoDetail: config-file-level facts for MongoDB (no auth, no data access).
type MongoDetail struct {
	ConfigPath    string `json:"config_path"`
	BindIP        string `json:"bind_ip,omitempty"`
	Port          int    `json:"port,omitempty"`
	ReplSet       string `json:"replica_set,omitempty"`
	Authorization string `json:"authorization,omitempty"`
	TLSMode       string `json:"tls_mode,omitempty"`
	DBPath        string `json:"db_path,omitempty"`
	ShardRole     string `json:"sharding_cluster_role,omitempty"`
}

type DBConfigFacts struct {
	Kind  string            `json:"kind"`
	Path  string            `json:"path"`
	Facts map[string]string `json:"facts"`
}

type Databases struct {
	Services []Service      `json:"services"`
	Mongo    []MongoDetail  `json:"mongodb,omitempty"`
	Configs  []DBConfigFacts `json:"config_facts,omitempty"`
}

type Firewall struct {
	Backends []string `json:"backends"`
	UFW      string   `json:"ufw_status,omitempty"`
	Rules    []string `json:"rules_summary,omitempty"`
	Note     string   `json:"note,omitempty"`
}

type Security struct {
	SSH        map[string]string `json:"sshd"`
	SSHConfig  string            `json:"sshd_config_path,omitempty"`
	Loose      []string          `json:"loose_permissions"`
	Sudoers    []string          `json:"sudo_group_members,omitempty"`
	LoginUsers []string          `json:"login_shell_users"`
}

type Timer struct {
	Unit      string `json:"unit"`
	Activates string `json:"activates"`
	Next      string `json:"next"`
	Last      string `json:"last"`
	Schedule  string `json:"schedule,omitempty"`
}

// PortExposure: one row of the open-port matrix.
type PortExposure struct {
	Proto     string `json:"proto"`
	Port      int    `json:"port"`
	Bind      string `json:"bind"`
	Scope     string `json:"scope"` // local only | private network | public IP | all interfaces
	Process   string `json:"process,omitempty"`
	PID       int    `json:"pid,omitempty"`
	Service   string `json:"service,omitempty"`
	Category  string `json:"category"`
	Container string `json:"container,omitempty"`
	Firewall  string `json:"firewall"`
	Risk      string `json:"risk"`
	Note      string `json:"note,omitempty"`
}

// ServiceUnit: detailed systemd service definition (read via systemctl show; secrets redacted).
type ServiceUnit struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Active      string   `json:"active"`
	Sub         string   `json:"sub"`
	Enabled     string   `json:"enabled"`
	Origin      string   `json:"origin"` // custom (/etc) | vendor (/lib,/usr/lib) | runtime | generated
	Fragment    string   `json:"unit_file"`
	DropIns     []string `json:"drop_ins,omitempty"`
	ExecStart   string   `json:"exec_start"`
	User        string   `json:"user"`
	WorkDir     string   `json:"working_directory,omitempty"`
	EnvFiles    []string `json:"environment_files,omitempty"`
	EnvKeys     []string `json:"environment_keys,omitempty"`
	Restart     string   `json:"restart"`
	MainPID     int      `json:"main_pid"`
	Memory      uint64   `json:"memory_bytes"`
	Since       string   `json:"active_since,omitempty"`
	Restarts    int      `json:"restarts"`
	Type        string   `json:"type"`
	WantedBy    string   `json:"wanted_by,omitempty"`
	Hardening   []string `json:"hardening,omitempty"`
	Risks       []string `json:"risks,omitempty"`
}
