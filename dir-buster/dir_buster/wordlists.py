"""A compact built-in wordlist so the tool works with no external files.

For real engagements point ``--wordlist`` at a large list such as those in
SecLists (e.g. ``Discovery/Web-Content/directory-list-2.3-medium.txt``).
"""

DEFAULT_PATHS = [
    # Common directories
    "admin", "administrator", "login", "logout", "dashboard", "panel",
    "cpanel", "webmail", "portal", "account", "accounts", "user", "users",
    "profile", "settings", "config", "configuration", "setup", "install",
    "api", "api/v1", "api/v2", "graphql", "rest", "swagger", "openapi",
    "app", "apps", "static", "assets", "public", "uploads", "upload",
    "files", "file", "images", "img", "media", "css", "js", "scripts",
    "backup", "backups", "bak", "old", "tmp", "temp", "cache", "logs",
    "log", "data", "db", "database", "sql", "dump", "export", "import",
    "test", "tests", "testing", "dev", "development", "staging", "demo",
    "docs", "doc", "documentation", "help", "support", "wiki", "blog",
    "news", "shop", "store", "cart", "checkout", "payment", "billing",
    "images", "internal", "private", "secret", "hidden", "secure",
    "server-status", "server-info", "phpinfo", "info", "status", "health",
    "healthz", "metrics", "debug", "console", "shell", "cmd", "cgi-bin",
    "wp-admin", "wp-content", "wp-includes", "wp-login.php", "xmlrpc.php",
    # Common files
    "robots.txt", "sitemap.xml", ".htaccess", ".htpasswd", ".env",
    ".git", ".git/config", ".gitignore", ".svn", ".DS_Store",
    "web.config", "config.php", "config.json", "settings.py", "wp-config.php",
    "index.php", "index.html", "readme.md", "README.md", "changelog.txt",
    "package.json", "composer.json", "Dockerfile", "docker-compose.yml",
    "id_rsa", "credentials", "secrets.json", "backup.zip", "backup.sql",
]

# File extensions worth appending to each word during a scan.
COMMON_EXTENSIONS = ["php", "html", "htm", "asp", "aspx", "jsp", "json", "txt", "bak", "zip"]
