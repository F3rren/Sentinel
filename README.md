# Sentinel

Sentinel is an **automated security testing** tool: given an application's address (e.g. `localhost:8080`), it discovers the exposed endpoints and launches automated attacks to find vulnerabilities, returning a report with severity and remediation guidance.

> **Intended use**: only against applications you are authorized to security-test (your own projects, staging environments, an authorized pentest target). Do not point it at third-party systems without explicit consent.

## What it does today

1. **Endpoint discovery**, in two phases:
   - **OpenAPI/Swagger** (preferred phase): tries to read a spec at `/v3/api-docs`, `/v2/api-docs`, `/swagger.json`, `/openapi.json`, etc. If the target is an API gateway aggregating multiple services (springdoc `swagger-config` or springfox `swagger-resources`), it follows the aggregation and fetches every downstream service's spec. When an operation documents a JSON `requestBody` (typical of POST/PUT/PATCH), it also generates a type-aware sample body (resolving `$ref`s against `components/schemas`: integers as numbers, booleans as booleans, strings with a consistent format), so the endpoint receives a request it can actually process instead of immediately rejecting it with 415/400 for a missing or wrongly-shaped body. Required properties are always populated; optional ones are populated too unless they carry a `pattern` constraint or are an array/object - values a generic sample can't safely guess without risking a validation failure that an absent field would otherwise skip. Fields with no format/enum/pattern constraint get a random, clearly-synthetic `sentinel-<token>` value rather than a plain word like "test" - easy to tell apart from real user data and to grep for in the target's logs/database afterward.
   - **HTML crawling**: if no spec is found (or in addition to it), it parses the target's page for links with a query string and forms, merging them (deduplicated) with whatever Swagger already found.
2. **Attack**, six modules:
   - **SQL Injection**: both error-based (fingerprinting MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, SQLite, and JDBC/Hibernate error messages) and boolean-based/blind (heuristic on injected true/false conditions). A response throttled by the target's own rate limiting (HTTP 429) on either side of the true/false comparison is treated as inconclusive rather than a signal, since it reflects Sentinel's own request volume, not the application's query logic.
   - **Missing Authentication**: flags endpoints that respond successfully (2xx) to a request carrying no credentials at all (Sentinel never sends an authentication header). A 401/403 response is treated as proof that authentication is enforced (no finding); any other status (400/404/5xx) is inconclusive and ignored. Thanks to the JSON body generated from the OpenAPI schema, this now also works for POST/PUT/PATCH endpoints that require a body - previously they almost always returned 415 (inconclusive), now they can receive a real response. This is deliberately narrower than a true IDOR/BOLA test (which would need two distinct authenticated identities to compare - a concept Sentinel doesn't have yet): it only answers "does this endpoint require authentication at all?".
   - **Brute Force**: on any `POST` endpoint shaped like a login (a JSON body, or form/query parameters, with both a password-like and a username/email-like field), tries a short list of common/default credential pairs (`admin`/`admin`, `admin`/`password`, `root`/`root`, ...). If one is accepted, it's reported as `WEAK_CREDENTIALS` (CRITICAL). Independently, if the target never responds with 429 (Too Many Requests) or 423 (Locked) across the whole attempt budget, it's reported as `MISSING_BRUTE_FORCE_PROTECTION` (LOW) - worded cautiously, since a small fixed attempt count not tripping a lockout doesn't prove one doesn't exist at a higher threshold. Kept deliberately small and fixed (`sentinel.scan.brute-force.max-attempts`, default 8) rather than an exhaustive wordlist, to keep a scan fast and avoid hammering a real login endpoint.
   - **Security Misconfiguration**: three independent, read-only checks on every `GET` endpoint's ordinary successful response - no fuzzing, so it runs safely on write endpoints' `GET` counterparts too. (1) **Missing security headers**: flags a response lacking `X-Content-Type-Options`, `X-Frame-Options`, or `Content-Security-Policy` (plus `Strict-Transport-Security` when the target is HTTPS) as `MISSING_SECURITY_HEADERS` (LOW). (2) **Permissive CORS**: sends one extra request carrying a hostile `Origin` header; if the response reflects it back verbatim (or answers with a bare `*`) in `Access-Control-Allow-Origin`, it's `PERMISSIVE_CORS` - HIGH if paired with `Access-Control-Allow-Credentials: true` (a real, exploitable cross-origin credential leak), MEDIUM otherwise. (3) **Server banner disclosure**: flags a `Server` header containing a version number, or any `X-Powered-By` header at all, as `SERVER_BANNER_DISCLOSURE` (LOW) - both make it trivial for an attacker to look up known CVEs for that exact version.
   - **XSS**: fuzzes each discovered parameter with a handful of classic markers (`<script>alert('sentinel-xss')</script>` and variants) and checks whether the exact payload comes back unescaped in the response body - a plain substring match, reliable here because the markers are synthetic strings unlikely to appear in legitimate content. Unescaped reflection alone doesn't prove exploitability: a browser only executes it if the response is actually rendered as HTML, so the finding is split by how the response identifies itself. `Content-Type` missing or containing `html` means a browser could plausibly render the body directly - a real, exploitable `REFLECTED_XSS` (HIGH). Anything else (JSON, plain text, ...) - the common case for the JSON APIs this tool mostly targets, where `<script>` inside a JSON string value is inert - is downgraded to `UNSANITIZED_INPUT_REFLECTION` (LOW): a genuine missing-output-encoding defect, but not one this response alone turns into script execution.
   - **Rate Limit**: fires a burst of back-to-back requests (`sentinel.scan.rate-limit.burst-size`, default 130) at each `GET` endpoint and checks whether the target ever throttles (429/423). If it never does, reports `MISSING_RATE_LIMITING` (LOW), worded with the same caution as the brute-force protection check. The burst needs to exceed the target's actual rate-limit capacity to be a meaningful test - raise `sentinel.scan.rate-limit.burst-size` (or `SENTINEL_SCAN_RATE_LIMIT_BURST_SIZE` via `.env`) if you know or suspect it allows more than the default before throttling. `GET`-only and read-only by construction: bursting a state-changing verb would amplify its side effects far more than the one-off calls the other modules make. Ordered to run strictly last among all modules, since its deliberate burst can exhaust a shared per-IP rate-limit bucket that covers every route, not just the one being bursted.
3. **Report**: JSON with every finding (endpoint, parameter, payload, evidence, recommendation, severity), a summary broken down **by severity and by issue type**, a numeric risk score alongside the qualitative rating, and a `narrative` field with a human-readable summary.

Modules planned for future iterations: IDOR/BOLA with multiple identities.

## Quick start

### From source

```bash
./mvnw spring-boot:run
```

The app starts on `http://localhost:8080`.

### With Docker, against an already-running "victim" app

If the victim already runs via its own `docker-compose`, Sentinel can join the same Docker network to reach it by container name instead of `localhost`:

```bash
cp .env.example .env
# open .env and set VICTIM_NETWORK_NAME to the victim's real network name
# (find it with: docker network ls)
docker compose up -d --build
```

Sentinel will be reachable at `http://localhost:8088`. Details and troubleshooting are in the comments of `docker-compose.yml` and `.env.example`.

**Fully automatic scan (zero manual commands)**: if you also set `SENTINEL_SCAN_AUTO_TARGET_URL` in `.env` to the victim's URL (e.g. `http://api-gateway:8080`), Sentinel waits on its own for the target to respond and launches the scan on container startup, with no manual request needed. The result can be checked at any time with:

```bash
curl http://localhost:8088/api/scans/latest
```

### Dev / test / prod environments

The `Dockerfile`/`docker-compose.yml`/`.env.example` above are the simple, one-size-fits-all path - fine for a quick scan. `Dockerfile.{dev,test,prod}` and `docker-compose.{dev,test,prod}.yml` split that into three environments that actually behave differently, not just three renamed copies:

| | `dev` | `test` | `prod` |
|---|---|---|---|
| Purpose | Fast local iteration against a victim you're actively testing | Run the Maven suite in a clean, reproducible container (CI or local) | Long-running, hardened deployment for a real engagement |
| Image | Maven+JDK, runs `spring-boot:run` straight from source | Maven+JDK, runs `mvn test` and exits | Multi-stage, final image is JRE + jar only, non-root user |
| Code changes | `src/` is bind-mounted - `docker compose restart sentinel` picks them up, no rebuild | N/A (one-shot) | None - redeploy by rebuilding the image |
| Defaults | `GET`-only, `DEBUG` HTTP logging | - | Every method, `INFO` HTTP logging |
| Lifecycle | `restart: "no"`, manual control | Exits after the run | `restart: unless-stopped`, memory/CPU ceiling |

Each environment reads its own `.env.<name>` (copy the matching `env.<name>.example` template) instead of sharing one `.env` - `docker compose` only auto-loads a file literally named `.env`, so switching environments needs the explicit `--env-file` flag:

```bash
# dev
cp env.dev.example .env.dev
docker compose -f docker-compose.dev.yml --env-file .env.dev up -d --build

# test (no victim involved, no --env-file needed unless tuning MAVEN_OPTS)
docker compose -f docker-compose.test.yml up --build --abort-on-container-exit

# prod
cp env.prod.example .env.prod
docker compose -f docker-compose.prod.yml --env-file .env.prod up -d --build
```

**Why bother splitting them**: the three environments want genuinely conflicting things from the same codebase - dev wants a fast edit-run loop and safe (`GET`-only) defaults since you're re-running the same scan repeatedly against your own test victim; test wants a throwaway, dependency-free way to get a trustworthy pass/fail without polluting a real environment's config; prod wants the smallest, least-privileged image and guardrails (restart policy, resource limits) appropriate for something left running unattended against a real authorized target. A single `Dockerfile`/`docker-compose.yml` can only really serve one of those well at a time - the others end up either slower than necessary (rebuilding an image on every dev change) or under-hardened (shipping Maven and source in what's meant to be a production image).

## Using the API

**Start a scan**

```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "http://localhost:9090"}'
```

Response (example):

```json
{
  "id": "…",
  "targetUrl": "http://localhost:9090",
  "endpointsDiscovered": 3,
  "endpointsTested": 3,
  "openApiSpecUrl": null,
  "findings": [ { "module": "sql-injection", "type": "SQL_INJECTION_ERROR_BASED", "severity": "CRITICAL", "...": "..." } ],
  "findingsByModule": { "sql-injection": [ { "module": "sql-injection", "type": "SQL_INJECTION_ERROR_BASED", "severity": "CRITICAL", "...": "..." } ] },
  "summary": {
    "totalFindings": 1,
    "overallRisk": "CRITICAL",
    "riskScore": 40,
    "possiblyRateLimited": false,
    "countsBySeverity": { "...": 0 },
    "countsByType": { "SQL_INJECTION_ERROR_BASED": 1, "SQL_INJECTION_BOOLEAN_BASED": 0, "MISSING_AUTHENTICATION": 0 }
  },
  "narrative": "Investigation of http://localhost:9090 completed in ... Detected 1 vulnerability (overall risk: CRITICAL, risk score: 40): 1 CRITICAL. By type: 1 SQL_INJECTION_ERROR_BASED."
}
```

Each finding also carries a `module` field (`sql-injection`, `missing-authentication`, `brute-force`, `security-misconfiguration`, `xss`, `rate-limit`) identifying which attack module produced it. `findingsByModule` is the same findings, grouped into one section per module (in the order the modules ran) - useful for a report broken down by attack type without re-grouping `findings` yourself. A module that reported nothing has no key there at all, rather than an empty array.

**`summary.possiblyRateLimited`**: a single module fuzzing many parameters across many endpoints (e.g. the SQL injection module trying several payloads per query parameter) can, by itself, generate enough requests to trip a real target's rate limiter well before the rest of the scan runs - every module tested afterwards then sees 429/423 instead of a real response, and an "all clean" report can actually mean "mostly untested," not "actually secure." Sentinel tracks the fraction of throttled responses across the whole scan; once at least 10 requests were made and 15% or more came back throttled, `possiblyRateLimited` is set to `true` and the `narrative` gets an explicit caveat (prefixed `WARNING:`) naming the exact ratio - read findings from a flagged scan as "no vulnerabilities found among the parts of the target that responded normally," not as a clean bill of health.

**Retrieve a previously generated report**

```bash
curl http://localhost:8080/api/scans/{id}
curl http://localhost:8080/api/scans/latest   # the most recent one, manual or automatic
```

**On file**: every completed scan is also saved as JSON in `reports/` (inside the project, configurable via `sentinel.scan.reports-directory`), named `<timestamp>-<host>-<scanId>.json` - useful for keeping, comparing, or versioning results without querying the API. With Docker, the folder is mounted to `./reports` on the host (see `docker-compose.yml`), so the files survive `docker compose down`.

## Configuration

Properties in `src/main/resources/application.properties` (overridable via environment variable too, e.g. `SENTINEL_SCAN_MAX_ENDPOINTS`):

| Property | Default | Description |
|---|---|---|
| `sentinel.scan.user-agent` | `Sentinel-Scanner/0.1 (+authorized-security-testing)` | User-Agent used on every request to the target |
| `sentinel.scan.request-timeout-ms` | `8000` | Timeout for a single HTTP request |
| `sentinel.scan.connect-timeout-ms` | `5000` | Connection timeout |
| `sentinel.scan.max-endpoints` | `25` | Maximum number of endpoints attacked per scan |
| `sentinel.scan.reports-directory` | `reports` | Folder where every report is also saved as a JSON file. Empty to disable file persistence |
| `sentinel.scan.allowed-http-methods` | `GET,POST,PUT,PATCH,DELETE` | Only endpoints with these methods get attacked (discovery still finds all of them). E.g. `GET` to guarantee a scan that never touches anything in writing |
| `sentinel.scan.auto-target-url` | _(empty)_ | If set, an automatic scan runs against this URL on startup, zero manual commands |
| `sentinel.scan.auto-scan-max-attempts` | `20` | Reachability attempts against the target before giving up on the auto-scan |
| `sentinel.scan.auto-scan-retry-delay-ms` | `3000` | Wait between one attempt and the next |
| `sentinel.scan.sql-injection.enabled` | `true` | Enables/disables the SQL injection module. When `false`, the module isn't even instantiated |
| `sentinel.scan.missing-authentication.enabled` | `true` | Enables/disables the Missing Authentication module |
| `sentinel.scan.brute-force.enabled` | `true` | Enables/disables the Brute Force module |
| `sentinel.scan.brute-force.max-attempts` | `8` | Number of common/default credential pairs tried per login-shaped endpoint before giving up |
| `sentinel.scan.security-misconfiguration.enabled` | `true` | Enables/disables the Security Misconfiguration module |
| `sentinel.scan.xss.enabled` | `true` | Enables/disables the XSS module |
| `sentinel.scan.rate-limit.enabled` | `true` | Enables/disables the Rate Limit module |
| `sentinel.scan.rate-limit.burst-size` | `130` | Number of back-to-back requests fired at each `GET` endpoint before concluding no throttling kicked in. Must exceed the target's real rate-limit capacity to be a meaningful test |

Every future attack module (IDOR/BOLA, ...) will follow the same `sentinel.scan.<module>.enabled` convention.

## Risk metric

Besides the list of findings, `summary` answers three different questions:

- **`countsBySeverity` / `overallRisk`** - how bad is the worst problem found (INFO → CRITICAL).
- **`countsByType`** - how many problems for each issue type (`SQL_INJECTION_ERROR_BASED`, `SQL_INJECTION_BOOLEAN_BASED`, `MISSING_AUTHENTICATION`, `WEAK_CREDENTIALS`, `MISSING_BRUTE_FORCE_PROTECTION`, `MISSING_SECURITY_HEADERS`, `PERMISSIVE_CORS`, `SERVER_BANNER_DISCLOSURE`, `REFLECTED_XSS`, `UNSANITIZED_INPUT_REFLECTION`, `MISSING_RATE_LIMITING`, ...), useful once more than one module is active and you want to know what to focus on.
- **`riskScore`** - a numeric score (weighted sum: CRITICAL=40, HIGH=20, MEDIUM=8, LOW=3, INFO=0) that distinguishes the *volume* of problems at equal `overallRisk`: 1 CRITICAL and 20 CRITICAL share the same `overallRisk`, but a very different score. It's a heuristic meant for comparing successive scans of the same target, not a CVSS or an "official" score.

## Development

```bash
./mvnw test   # runs the whole suite
```

## Stack

Java 17, Spring Boot, Jsoup (HTML parsing), Jackson (OpenAPI parsing). Scans run synchronously; reports are kept in memory for retrieval by id during the app's lifetime, and are also persisted as JSON files under `reports/` (see [Using the API](#using-the-api)).
