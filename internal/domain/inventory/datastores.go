package inventory

// Authenticated, read-only data-store inspection results. Metadata only: no rows, keys, values or secrets.

type PGDatabase struct {
	Name        string    `json:"name"`
	Owner       string    `json:"owner"`
	Encoding    string    `json:"encoding"`
	Collate     string    `json:"collate"`
	ConnLimit   int       `json:"conn_limit"`
	AllowConn   bool      `json:"allow_conn"`
	IsTemplate  bool      `json:"is_template"`
	SizeBytes   int64     `json:"size_bytes"`
	Connections int       `json:"connections"`
	Detail      *PGDBDetail `json:"detail,omitempty"`
}

type PGTable struct {
	Name          string `json:"name"`
	TotalBytes    int64  `json:"total_bytes"`
	HeapBytes     int64  `json:"heap_bytes"`
	EstRows       int64  `json:"est_rows"`
	DeadTuples    int64  `json:"dead_tuples"`
	LastAutovac   string `json:"last_autovacuum"`
	LastAutoanaly string `json:"last_autoanalyze"`
}

type PGDBDetail struct {
	Schemas    []string         `json:"schemas"`
	Extensions []string         `json:"extensions"`
	Counts     map[string]int64 `json:"object_counts"`
	Tables     []PGTable        `json:"largest_tables"`
	Error      string           `json:"error,omitempty"`
}

type PGRole struct {
	Name        string   `json:"name"`
	Login       bool     `json:"login"`
	Superuser   bool     `json:"superuser"`
	CreateDB    bool     `json:"createdb"`
	CreateRole  bool     `json:"createrole"`
	Replication bool     `json:"replication"`
	BypassRLS   bool     `json:"bypassrls"`
	ConnLimit   int      `json:"conn_limit"`
	ValidUntil  string   `json:"valid_until"`
	MemberOf    []string `json:"member_of"`
}

type PGHBARule struct {
	Line     int      `json:"line"`
	Type     string   `json:"type"`
	Database []string `json:"database"`
	User     []string `json:"user_name"`
	Address  string   `json:"address"`
	Netmask  string   `json:"netmask"`
	Auth     string   `json:"auth_method"`
	Error    string   `json:"error"`
	Meaning  string   `json:"meaning"`
}

type PGActivity struct {
	Database   string `json:"datname"`
	User       string `json:"usename"`
	State      string `json:"state"`
	Client     string `json:"client"`
	N          int    `json:"n"`
	MaxQuerySec int   `json:"max_query_sec"`
	MaxXactSec  int   `json:"max_xact_sec"`
}

type PGReplica struct {
	Client    string `json:"client"`
	App       string `json:"app"`
	State     string `json:"state"`
	Sync      string `json:"sync"`
	ReplayLag string `json:"replay_lag"`
}

type PGSlot struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	Active   bool   `json:"active"`
	Database string `json:"database"`
	Retained string `json:"retained_wal"`
}

type PGInstance struct {
	Target       string            `json:"target"`  // redacted endpoint description
	Via          string            `json:"via"`     // dsn | local-psql | docker-exec
	Version      string            `json:"version"`
	InRecovery   bool              `json:"in_recovery"`
	Settings     map[string]string `json:"settings"`
	Databases    []PGDatabase      `json:"databases"`
	Roles        []PGRole          `json:"roles"`
	HBA          []PGHBARule       `json:"hba_rules"`
	HBANote      string            `json:"hba_note,omitempty"`
	Activity     []PGActivity      `json:"activity"`
	WaitingLocks int               `json:"waiting_locks"`
	Replicas     []PGReplica       `json:"replicas"`
	Slots        []PGSlot          `json:"replication_slots"`
	UpstreamHost string            `json:"wal_receiver_sender,omitempty"`
	Exposure     []string          `json:"exposure"` // who can connect, in plain words
	Errors       []string          `json:"errors,omitempty"`
}

type Postgres struct {
	Instances []PGInstance `json:"instances"`
	Skipped   []string     `json:"skipped,omitempty"`
}

type RedisClientGroup struct {
	Addr  string `json:"addr"`
	User  string `json:"user"`
	Count int    `json:"count"`
	DBs   string `json:"dbs"`
}

type RedisInstance struct {
	Target     string              `json:"target"`
	Via        string              `json:"via"`
	AuthNeeded bool                `json:"auth_required"`
	Error      string              `json:"error,omitempty"`
	Info       map[string]string   `json:"info"`   // selected INFO fields
	Config     map[string]string   `json:"config"` // CONFIG GET (non-secret keys)
	Keyspace   map[string]string   `json:"keyspace"`
	Users      []string            `json:"acl_users"` // flags only, passwords stripped
	Clients    []RedisClientGroup  `json:"clients"`
	Replicas   []string            `json:"replicas"`
	Cluster    map[string]string   `json:"cluster,omitempty"`
	Exposure   []string            `json:"exposure"`
}

type Redis struct {
	Instances []RedisInstance `json:"instances"`
	Skipped   []string        `json:"skipped,omitempty"`
}

type MySQLDatabase struct {
	Name       string           `json:"name"`
	Charset    string           `json:"charset"`
	Collation  string           `json:"collation"`
	Tables     int64            `json:"tables"`
	DataBytes  int64            `json:"data_bytes"`
	IndexBytes int64            `json:"index_bytes"`
	FreeBytes  int64            `json:"data_free_bytes"`
	EstRows    int64            `json:"est_rows"`
	Engines    map[string]int64 `json:"engines"`
	Views      int64            `json:"views"`
	Routines   int64            `json:"routines"`
	Triggers   int64            `json:"triggers"`
	Events     int64            `json:"events"`
	NoPK       int64            `json:"tables_without_pk"`
	System     bool             `json:"system"`
}

type MySQLTable struct {
	Schema     string `json:"schema"`
	Name       string `json:"name"`
	Engine     string `json:"engine"`
	EstRows    int64  `json:"est_rows"`
	DataBytes  int64  `json:"data_bytes"`
	IndexBytes int64  `json:"index_bytes"`
	FreeBytes  int64  `json:"data_free_bytes"`
	Updated    string `json:"update_time"`
}

type MySQLUser struct {
	User          string   `json:"user"`
	Host          string   `json:"host"`
	Plugin        string   `json:"plugin"`
	EmptyPassword bool     `json:"empty_password"`
	Global        []string `json:"global_privs"` // dangerous globals only
	Schemas       []string `json:"schema_grants"`
}

type MySQLConn struct {
	User    string `json:"user"`
	Host    string `json:"host"`
	DB      string `json:"db"`
	Command string `json:"command"`
	N       int    `json:"n"`
	MaxTime int    `json:"max_time_sec"`
}

type MySQLInstance struct {
	Target      string            `json:"target"`
	Via         string            `json:"via"`
	Flavor      string            `json:"flavor"`
	Variables   map[string]string `json:"variables"`
	Status      map[string]string `json:"status"`
	Databases   []MySQLDatabase   `json:"databases"`
	Largest     []MySQLTable      `json:"largest_tables"`
	NoPKTables  []string          `json:"tables_without_pk"`
	Users       []MySQLUser       `json:"users"`
	Connections []MySQLConn       `json:"connections"`
	Replica     map[string]string `json:"replica_status,omitempty"`
	Binlog      map[string]string `json:"binlog_status,omitempty"`
	Group       []string          `json:"group_replication_members,omitempty"`
	Galera      map[string]string `json:"galera,omitempty"`
	Exposure    []string          `json:"exposure"`
	Analysis    []string          `json:"analysis"`
	Errors      []string          `json:"errors,omitempty"`
}

type MySQL struct {
	Instances []MySQLInstance `json:"instances"`
	Skipped   []string        `json:"skipped,omitempty"`
}

// DBConfigFile: active (non-comment) directives of a datastore config file, secrets masked.
type DBConfigFile struct {
	Engine string   `json:"engine"`
	Where  string   `json:"where"` // host | container:<name>
	Path   string   `json:"path"`
	Lines  []string `json:"active_lines"`
	Total  int      `json:"total_lines"`
	Error  string   `json:"error,omitempty"`
}

type DBConfigs struct {
	Files []DBConfigFile `json:"files"`
	Notes []string       `json:"notes,omitempty"`
}

// DBAccessCheck: live connect test from this host to a DB port, then an unauthenticated protocol handshake.
type DBAccessCheck struct {
	Engine  string `json:"engine"`
	Owner   string `json:"owner"`   // container or process
	Address string `json:"address"` // address dialed
	Port    int    `json:"port"`
	Path    string `json:"path"`   // loopback | LAN <ip> | not published
	TCP     string `json:"tcp"`    // open | closed | timeout
	Auth    string `json:"auth"`   // what the server demands from an anonymous client
	Verdict string `json:"verdict"`
	Detail  string `json:"detail,omitempty"`
}

type DBAccess struct {
	Checks []DBAccessCheck `json:"checks"`
	Note   string          `json:"note"`
}

// ServiceCheck: metadata for brokers, secret stores, search, object storage, coordination services.
type ServiceCheck struct {
	Kind     string            `json:"kind"`
	Owner    string            `json:"owner"`
	Endpoint string            `json:"endpoint,omitempty"`
	Auth     string            `json:"auth"` // what an anonymous request gets
	Facts    map[string]string `json:"facts"`
	Notes    []string          `json:"notes,omitempty"`
}

type Services struct {
	Checks []ServiceCheck `json:"checks"`
}

type Tool struct {
	Name     string   `json:"name"`
	Category string   `json:"category"`
	Evidence []string `json:"evidence"`
	Version  string   `json:"version,omitempty"`
	Running  bool     `json:"running"`
	Ports    []int    `json:"ports,omitempty"`
	UI       string   `json:"ui,omitempty"` // reachable web UI: url + HTTP status
}

type Tools struct {
	Items      []Tool         `json:"tools"`
	ByCategory map[string]int `json:"by_category"`
}
