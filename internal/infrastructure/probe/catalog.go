package probe

// Signature catalog for DevOps tooling and extra data stores. Data only.

type toolSig struct {
	name, cat string
	bins      []string // CLI in PATH
	procs     []string // process comm / java main hint
	images    []string // container image substrings
	ports     []int
	units     []string // systemd unit prefixes
	paths     []string // config/data dirs
	ver       []string // fixed version argv (CLI tools only)
}

var toolCatalog = []toolSig{
	// CI/CD
	{"Jenkins", "CI/CD", nil, []string{"jenkins"}, []string{"jenkins"}, []int{8080, 50000}, []string{"jenkins"}, []string{"/var/lib/jenkins", "/etc/default/jenkins"}, nil},
	{"GitLab", "CI/CD", []string{"gitlab-ctl"}, []string{"gitlab-workhorse", "puma"}, []string{"gitlab/gitlab-ce", "gitlab/gitlab-ee"}, nil, []string{"gitlab-runsvdir"}, []string{"/etc/gitlab"}, nil},
	{"GitLab Runner", "CI/CD", []string{"gitlab-runner"}, []string{"gitlab-runner"}, []string{"gitlab-runner"}, nil, []string{"gitlab-runner"}, []string{"/etc/gitlab-runner"}, []string{"gitlab-runner", "--version"}},
	{"GitHub Actions runner", "CI/CD", nil, []string{"Runner.Listener", "Runner.Worker"}, []string{"actions-runner"}, nil, []string{"actions.runner"}, nil, nil},
	{"Drone / Woodpecker", "CI/CD", nil, []string{"drone-server", "drone-runner", "woodpecker"}, []string{"drone/drone", "woodpeckerci"}, nil, nil, nil, nil},
	{"TeamCity", "CI/CD", nil, []string{"teamcity"}, []string{"jetbrains/teamcity"}, []int{8111}, nil, nil, nil},
	{"Argo CD", "CI/CD", []string{"argocd"}, []string{"argocd-server"}, []string{"argoproj/argocd", "argo-cd"}, nil, nil, nil, []string{"argocd", "version", "--client", "--short"}},
	{"Flux", "CI/CD", []string{"flux"}, []string{"source-controller", "kustomize-controller"}, []string{"fluxcd"}, nil, nil, nil, []string{"flux", "--version"}},
	{"Gitea / Forgejo", "CI/CD", []string{"gitea", "forgejo"}, []string{"gitea", "forgejo"}, []string{"gitea/gitea", "forgejo"}, []int{3000}, []string{"gitea", "forgejo"}, []string{"/etc/gitea"}, nil},
	// Registries / artifacts
	{"Harbor", "Registry", nil, []string{"harbor-core"}, []string{"goharbor"}, nil, nil, nil, nil},
	{"Docker Registry", "Registry", nil, []string{"registry"}, []string{"registry:"}, []int{5000}, nil, nil, nil},
	{"Nexus", "Registry", nil, []string{"nexus"}, []string{"sonatype/nexus"}, []int{8081}, []string{"nexus"}, nil, nil},
	{"Artifactory", "Registry", nil, []string{"artifactory"}, []string{"jfrog/artifactory"}, []int{8082}, nil, nil, nil},
	// Monitoring
	{"Prometheus", "Monitoring", []string{"prometheus"}, []string{"prometheus"}, []string{"prom/prometheus", "prometheus:"}, []int{9090}, []string{"prometheus"}, []string{"/etc/prometheus"}, nil},
	{"Alertmanager", "Monitoring", nil, []string{"alertmanager"}, []string{"alertmanager"}, []int{9093}, []string{"alertmanager"}, []string{"/etc/alertmanager"}, nil},
	{"Grafana", "Monitoring", nil, []string{"grafana", "grafana-server"}, []string{"grafana/grafana"}, []int{3000}, []string{"grafana-server"}, []string{"/etc/grafana"}, nil},
	{"node_exporter", "Monitoring", nil, []string{"node_exporter"}, []string{"node-exporter"}, []int{9100}, []string{"node_exporter", "prometheus-node-exporter"}, nil, nil},
	{"cAdvisor", "Monitoring", nil, []string{"cadvisor"}, []string{"cadvisor"}, []int{8080}, nil, nil, nil},
	{"Zabbix", "Monitoring", nil, []string{"zabbix_server", "zabbix_agentd", "zabbix_agent2"}, []string{"zabbix"}, []int{10050, 10051}, []string{"zabbix"}, []string{"/etc/zabbix"}, nil},
	{"Netdata", "Monitoring", nil, []string{"netdata"}, []string{"netdata"}, []int{19999}, []string{"netdata"}, []string{"/etc/netdata"}, nil},
	{"Datadog agent", "Monitoring", nil, []string{"datadog-agent"}, []string{"datadog/agent"}, []int{8125, 8126}, []string{"datadog-agent"}, []string{"/etc/datadog-agent"}, nil},
	{"Grafana Alloy / Agent", "Monitoring", nil, []string{"alloy", "grafana-agent"}, []string{"grafana/alloy", "grafana/agent"}, []int{12345}, []string{"alloy", "grafana-agent"}, []string{"/etc/alloy"}, nil},
	{"Telegraf", "Monitoring", nil, []string{"telegraf"}, []string{"telegraf"}, nil, []string{"telegraf"}, []string{"/etc/telegraf"}, nil},
	{"Uptime Kuma", "Monitoring", nil, nil, []string{"uptime-kuma"}, []int{3001}, nil, nil, nil},
	{"Sentry", "Monitoring", nil, nil, []string{"getsentry/sentry"}, []int{9000}, nil, nil, nil},
	{"Jaeger / Tempo", "Tracing", nil, []string{"jaeger", "tempo"}, []string{"jaegertracing", "grafana/tempo"}, []int{16686, 3200}, nil, nil, nil},
	{"OpenTelemetry Collector", "Tracing", nil, []string{"otelcol", "otelcol-contrib"}, []string{"opentelemetry-collector"}, []int{4317, 4318}, []string{"otelcol"}, nil, nil},
	// Logging
	{"Loki", "Logging", nil, []string{"loki"}, []string{"grafana/loki"}, []int{3100}, []string{"loki"}, nil, nil},
	{"Promtail", "Logging", nil, []string{"promtail"}, []string{"grafana/promtail"}, nil, []string{"promtail"}, nil, nil},
	{"Fluentd / Fluent Bit", "Logging", nil, []string{"fluentd", "fluent-bit", "td-agent"}, []string{"fluentd", "fluent-bit"}, []int{24224}, []string{"fluentd", "fluent-bit", "td-agent"}, nil, nil},
	{"Filebeat / Metricbeat", "Logging", nil, []string{"filebeat", "metricbeat", "auditbeat"}, []string{"beats/"}, nil, []string{"filebeat", "metricbeat"}, []string{"/etc/filebeat"}, nil},
	{"Logstash", "Logging", nil, []string{"logstash"}, []string{"logstash"}, []int{5044, 9600}, []string{"logstash"}, []string{"/etc/logstash"}, nil},
	{"Kibana", "Logging", nil, []string{"kibana"}, []string{"kibana"}, []int{5601}, []string{"kibana"}, []string{"/etc/kibana"}, nil},
	{"Graylog", "Logging", nil, []string{"graylog"}, []string{"graylog"}, []int{9000}, []string{"graylog-server"}, nil, nil},
	{"Vector", "Logging", []string{"vector"}, []string{"vector"}, []string{"timberio/vector"}, []int{8686}, []string{"vector"}, []string{"/etc/vector"}, nil},
	// Proxies / LB / gateways
	{"Nginx", "Proxy/LB", []string{"nginx"}, []string{"nginx"}, []string{"nginx"}, nil, []string{"nginx"}, []string{"/etc/nginx"}, nil},
	{"Apache httpd", "Proxy/LB", []string{"apache2", "httpd"}, []string{"apache2", "httpd"}, []string{"httpd"}, nil, []string{"apache2", "httpd"}, []string{"/etc/apache2", "/etc/httpd"}, nil},
	{"HAProxy", "Proxy/LB", []string{"haproxy"}, []string{"haproxy"}, []string{"haproxy"}, nil, []string{"haproxy"}, []string{"/etc/haproxy"}, nil},
	{"Traefik", "Proxy/LB", nil, []string{"traefik"}, []string{"traefik"}, []int{8080}, []string{"traefik"}, []string{"/etc/traefik"}, nil},
	{"Caddy", "Proxy/LB", []string{"caddy"}, []string{"caddy"}, []string{"caddy"}, []int{2019}, []string{"caddy"}, []string{"/etc/caddy"}, nil},
	{"Envoy", "Proxy/LB", nil, []string{"envoy"}, []string{"envoyproxy"}, []int{9901}, nil, nil, nil},
	{"Kong", "Proxy/LB", nil, []string{"kong"}, []string{"kong"}, []int{8001}, nil, nil, nil},
	{"Nginx Proxy Manager", "Proxy/LB", nil, nil, []string{"nginx-proxy-manager"}, []int{81}, nil, nil, nil},
	// Orchestration / runtime
	{"Docker", "Containers", []string{"docker"}, []string{"dockerd"}, nil, nil, []string{"docker"}, []string{"/etc/docker"}, []string{"docker", "--version"}},
	{"Docker Compose", "Containers", []string{"docker-compose"}, nil, nil, nil, nil, nil, []string{"docker-compose", "--version"}},
	{"Podman", "Containers", []string{"podman"}, []string{"podman"}, nil, nil, []string{"podman"}, nil, []string{"podman", "--version"}},
	{"containerd", "Containers", []string{"ctr", "nerdctl"}, []string{"containerd"}, nil, nil, []string{"containerd"}, []string{"/etc/containerd"}, nil},
	{"Portainer", "Containers", nil, nil, []string{"portainer"}, []int{9443, 9000}, nil, nil, nil},
	{"Watchtower", "Containers", nil, nil, []string{"watchtower"}, nil, nil, nil, nil},
	{"kubectl", "Kubernetes", []string{"kubectl"}, nil, nil, nil, nil, nil, []string{"kubectl", "version", "--client"}},
	{"Helm", "Kubernetes", []string{"helm"}, nil, nil, nil, nil, nil, []string{"helm", "version", "--short"}},
	{"k9s", "Kubernetes", []string{"k9s"}, nil, nil, nil, nil, nil, nil},
	{"kind / minikube / k3d", "Kubernetes", []string{"kind", "minikube", "k3d"}, nil, []string{"kindest/node", "rancher/k3s"}, nil, nil, nil, nil},
	{"Rancher", "Kubernetes", nil, nil, []string{"rancher/rancher"}, nil, nil, nil, nil},
	{"Nomad", "Orchestration", []string{"nomad"}, []string{"nomad"}, []string{"hashicorp/nomad"}, []int{4646}, []string{"nomad"}, []string{"/etc/nomad.d"}, []string{"nomad", "version"}},
	// IaC / config mgmt
	{"Terraform", "IaC", []string{"terraform"}, nil, nil, nil, nil, nil, []string{"terraform", "version"}},
	{"OpenTofu", "IaC", []string{"tofu"}, nil, nil, nil, nil, nil, []string{"tofu", "version"}},
	{"Ansible", "IaC", []string{"ansible", "ansible-playbook"}, nil, nil, nil, nil, []string{"/etc/ansible"}, []string{"ansible", "--version"}},
	{"Packer", "IaC", []string{"packer"}, nil, nil, nil, nil, nil, []string{"packer", "version"}},
	{"Pulumi", "IaC", []string{"pulumi"}, nil, nil, nil, nil, nil, []string{"pulumi", "version"}},
	{"Puppet", "IaC", []string{"puppet"}, []string{"puppet"}, nil, nil, []string{"puppet"}, []string{"/etc/puppetlabs"}, nil},
	{"Chef", "IaC", []string{"chef-client"}, []string{"chef-client"}, nil, nil, []string{"chef-client"}, []string{"/etc/chef"}, nil},
	{"SaltStack", "IaC", []string{"salt-minion", "salt-call"}, []string{"salt-minion", "salt-master"}, nil, []int{4505, 4506}, []string{"salt-minion", "salt-master"}, []string{"/etc/salt"}, nil},
	// Cloud CLIs
	{"AWS CLI", "Cloud CLI", []string{"aws"}, nil, nil, nil, nil, nil, []string{"aws", "--version"}},
	{"gcloud", "Cloud CLI", []string{"gcloud"}, nil, nil, nil, nil, nil, nil},
	{"Azure CLI", "Cloud CLI", []string{"az"}, nil, nil, nil, nil, nil, nil},
	{"doctl / hcloud", "Cloud CLI", []string{"doctl", "hcloud"}, nil, nil, nil, nil, nil, nil},
	// Security / identity
	{"Keycloak", "Identity", nil, []string{"keycloak"}, []string{"keycloak"}, []int{8080}, nil, nil, nil},
	{"Authentik / Authelia", "Identity", nil, nil, []string{"goauthentik", "authelia"}, []int{9000, 9091}, nil, nil, nil},
	{"fail2ban", "Security", []string{"fail2ban-client"}, []string{"fail2ban-server"}, nil, nil, []string{"fail2ban"}, []string{"/etc/fail2ban"}, nil},
	{"CrowdSec", "Security", []string{"cscli"}, []string{"crowdsec"}, []string{"crowdsecurity"}, nil, []string{"crowdsec"}, nil, nil},
	{"Wazuh / OSSEC", "Security", nil, []string{"wazuh-agentd", "ossec"}, []string{"wazuh"}, []int{1514, 1515}, []string{"wazuh-agent"}, []string{"/var/ossec"}, nil},
	{"Trivy", "Security", []string{"trivy"}, nil, nil, nil, nil, nil, []string{"trivy", "--version"}},
	{"WireGuard", "VPN", []string{"wg"}, nil, []string{"wireguard", "wg-easy"}, []int{51820}, []string{"wg-quick"}, []string{"/etc/wireguard"}, nil},
	{"OpenVPN", "VPN", []string{"openvpn"}, []string{"openvpn"}, []string{"openvpn"}, []int{1194}, []string{"openvpn"}, []string{"/etc/openvpn"}, nil},
	{"Tailscale", "VPN", []string{"tailscale"}, []string{"tailscaled"}, []string{"tailscale"}, nil, []string{"tailscaled"}, nil, nil},
	// Workflow / apps
	{"Airflow", "Workflow", nil, []string{"airflow"}, []string{"apache/airflow"}, []int{8080}, nil, nil, nil},
	{"n8n", "Workflow", nil, nil, []string{"n8nio/n8n"}, []int{5678}, nil, nil, nil},
	{"Temporal", "Workflow", nil, nil, []string{"temporalio"}, []int{7233}, nil, nil, nil},
	{"SonarQube", "Code quality", nil, []string{"sonar"}, []string{"sonarqube"}, []int{9000}, nil, nil, nil},
	{"PM2", "Process manager", []string{"pm2"}, []string{"PM2"}, nil, nil, nil, nil, nil},
	{"Supervisor", "Process manager", []string{"supervisorctl"}, []string{"supervisord"}, nil, nil, []string{"supervisor"}, []string{"/etc/supervisor"}, nil},
	{"Certbot", "TLS", []string{"certbot"}, nil, nil, nil, []string{"certbot"}, []string{"/etc/letsencrypt"}, nil},
	// Runtimes
	{"Go", "Runtime", []string{"go"}, nil, nil, nil, nil, nil, []string{"go", "version"}},
	{"Node.js", "Runtime", []string{"node"}, nil, nil, nil, nil, nil, []string{"node", "--version"}},
	{"Python", "Runtime", []string{"python3"}, nil, nil, nil, nil, nil, []string{"python3", "--version"}},
	{"Java", "Runtime", []string{"java"}, nil, nil, nil, nil, nil, nil},
	{"PHP", "Runtime", []string{"php"}, []string{"php-fpm"}, nil, nil, []string{"php"}, nil, []string{"php", "--version"}},
}

// extra data stores appended to dbSigs at init (detected + TCP-checked + config-read like the others)
var extraDBSigs = []dbSig{
	{"neo4j", []string{"neo4j"}, []int{7474, 7687}, []string{"neo4j"}, []string{"/etc/neo4j/neo4j.conf"}},
	{"couchdb", []string{"couchdb"}, []int{5984}, []string{"couchdb"}, []string{"/opt/couchdb/etc/local.ini"}},
	{"couchbase", []string{"couchbase-server"}, []int{8091}, []string{"couchbase"}, nil},
	{"cockroachdb", []string{"cockroach"}, []int{26257, 8080}, []string{"cockroachdb"}, nil},
	{"tidb", []string{"tidb-server"}, []int{4000}, []string{"pingcap/tidb"}, nil},
	{"scylladb", []string{"scylla"}, []int{9042}, []string{"scylladb"}, []string{"/etc/scylla/scylla.yaml"}},
	{"questdb", []string{"questdb"}, []int{9009, 8812}, []string{"questdb"}, nil},
	{"victoriametrics", []string{"victoria-metrics", "vmstorage"}, []int{8428}, []string{"victoriametrics"}, nil},
	{"timescaledb", nil, nil, []string{"timescale"}, nil},
	{"solr", []string{"solr"}, []int{8983}, []string{"solr"}, nil},
	{"meilisearch", []string{"meilisearch"}, []int{7700}, []string{"meilisearch"}, nil},
	{"typesense", []string{"typesense-server"}, []int{8108}, []string{"typesense"}, nil},
	{"qdrant", []string{"qdrant"}, []int{6333, 6334}, []string{"qdrant"}, nil},
	{"milvus", []string{"milvus"}, []int{19530}, []string{"milvus"}, nil},
	{"weaviate", []string{"weaviate"}, []int{8080}, []string{"weaviate"}, nil},
	{"chroma", nil, []int{8000}, []string{"chromadb"}, nil},
	{"arangodb", []string{"arangod"}, []int{8529}, []string{"arangodb"}, nil},
	{"surrealdb", []string{"surreal"}, []int{8000}, []string{"surrealdb"}, nil},
	{"mssql", []string{"sqlservr"}, []int{1433}, []string{"mssql"}, nil},
	{"oracle", []string{"tnslsnr", "ora_pmon"}, []int{1521}, []string{"oracle"}, nil},
	{"keydb", []string{"keydb-server"}, []int{6379}, []string{"keydb"}, nil},
	{"dragonfly", []string{"dragonfly"}, []int{6379}, []string{"dragonflydb"}, nil},
	{"pulsar", []string{"pulsar"}, []int{6650, 8080}, []string{"apachepulsar"}, nil},
	{"activemq", []string{"activemq"}, []int{61616, 8161}, []string{"activemq"}, nil},
	{"mosquitto", []string{"mosquitto"}, []int{1883, 8883}, []string{"mosquitto"}, []string{"/etc/mosquitto/mosquitto.conf"}},
	{"emqx", []string{"emqx"}, []int{1883, 18083}, []string{"emqx"}, nil},
	{"nsq", []string{"nsqd"}, []int{4150, 4151}, []string{"nsqio"}, nil},
	{"redpanda", []string{"redpanda"}, []int{9092, 9644}, []string{"redpanda"}, nil},
	{"hbase", []string{"hbase"}, []int{16010}, []string{"hbase"}, nil},
	{"druid", []string{"druid"}, []int{8888}, []string{"apache/druid"}, nil},
	}

func init() {
	for _, s := range extraDBSigs {
		if len(s.procs)+len(s.images)+len(s.configs) > 0 {
			dbSigs = append(dbSigs, s)
		}
	}
}

// baseDBSigs: classic engines where port-only detection is meaningful (extras share common ports).
var baseDBSigs = len(dbSigs)
