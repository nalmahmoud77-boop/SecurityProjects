"""Built-in data: a small default subdomain wordlist and common TCP ports.

The wordlist is intentionally compact so the tool works out of the box with no
external files. Point ``--wordlist`` at a bigger list (e.g. SecLists) for real
engagements.
"""

# A curated set of the subdomains that appear most often in the wild.
DEFAULT_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "dns", "mx", "email", "cpanel", "whm", "autodiscover", "autoconfig",
    "admin", "administrator", "portal", "dashboard", "panel", "manage",
    "api", "api-dev", "apis", "gateway", "graphql", "rest",
    "dev", "development", "staging", "stage", "test", "testing", "qa",
    "uat", "sandbox", "demo", "beta", "alpha", "preprod", "prod",
    "app", "apps", "mobile", "m", "web", "www2", "cdn", "static",
    "assets", "img", "images", "media", "files", "download", "downloads",
    "docs", "documentation", "help", "support", "kb", "wiki", "status",
    "blog", "news", "forum", "community", "shop", "store", "cart", "pay",
    "vpn", "remote", "gateway", "git", "gitlab", "jenkins", "ci", "build",
    "jira", "confluence", "grafana", "kibana", "prometheus", "monitor",
    "db", "database", "sql", "mysql", "postgres", "redis", "mongo",
    "internal", "intranet", "corp", "secure", "login", "auth", "sso",
    "office", "exchange", "owa", "lync", "teams", "vault", "backup",
]

# (port, service name) pairs for a light "top ports" scan.
COMMON_PORTS = [
    (21, "ftp"), (22, "ssh"), (23, "telnet"), (25, "smtp"),
    (53, "dns"), (80, "http"), (110, "pop3"), (135, "msrpc"),
    (139, "netbios"), (143, "imap"), (443, "https"), (445, "smb"),
    (993, "imaps"), (995, "pop3s"), (1433, "mssql"), (1723, "pptp"),
    (3306, "mysql"), (3389, "rdp"), (5432, "postgres"), (5900, "vnc"),
    (6379, "redis"), (8000, "http-alt"), (8080, "http-proxy"),
    (8443, "https-alt"), (8888, "http-alt"), (9200, "elasticsearch"),
    (11211, "memcached"), (27017, "mongodb"),
]


def top_ports(n):
    """Return the first ``n`` common ports as (port, service) tuples."""
    return COMMON_PORTS[: max(0, n)]
