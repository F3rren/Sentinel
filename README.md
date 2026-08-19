# Sentinel

Sentinel is an **automated security testing** tool: given an application's address (e.g. `localhost:8080`), it discovers the exposed endpoints and launches automated attacks to find vulnerabilities, returning a report with severity and remediation guidance.

> **Intended use**: only against applications you are authorized to security-test (your own projects, staging environments, an authorized pentest target). Do not point it at third-party systems without explicit consent.

## What it does today

1. **Endpoint discovery**, in two phases:
   - **OpenAPI/Swagger** (preferred phase): tries to read a spec at `/v3/api-docs`, `/v2/api-docs`, `/swagger.json`, `/openapi.json`, etc. If the target is an API gateway aggregating multiple services (springdoc `swagger-config` or springfox `swagger-resources`), it follows the aggregation and fetches every downstream service's spec. When an operation documents a JSON `requestBody` (typical of POST/PUT/PATCH), it also generates a type-aware sample body (resolving `$ref`s against `components/schemas`: integers as numbers, booleans as booleans, strings with a consistent format), so the endpoint receives a request it can actually process instead of immediately rejecting it with 415/400 for a missing or wrongly-shaped body. Required properties are always populated; optional ones are populated too unless they carry a `pattern` constraint or are an array/object - values a generic sample can't safely guess without risking a validation failure that an absent field would otherwise skip. Fields with no format/enum/pattern constraint get a random, clearly-synthetic `sentinel-<token>` value rather than a plain word like "test" - easy to tell apart from real user data and to grep for in the target's logs/database afterward.
   - **HTML crawling**: if no spec is found (or in addition to it), it parses the target's page for links with a query string and forms, merging them (deduplicated) with whatever Swagger already found.
2. **Attack**, fourteen modules:
   - **SQL Injection**: both error-based (fingerprinting MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, SQLite, and JDBC/Hibernate error messages) and boolean-based/blind (heuristic on injected true/false conditions). A response throttled by the target's own rate limiting (HTTP 429) on either side of the true/false comparison is treated as inconclusive rather than a signal, since it reflects Sentinel's own request volume, not the application's query logic.
   - **Missing Authentication**: flags endpoints that respond successfully (2xx) to a request carrying no credentials at all (Sentinel never sends an authentication header). A 401/403 response is treated as proof that authentication is enforced (no finding); any other status (400/404/5xx) is inconclusive and ignored. Thanks to the JSON body generated from the OpenAPI schema, this now also works for POST/PUT/PATCH endpoints that require a body - previously they almost always returned 415 (inconclusive), now they can receive a real response. This only answers "does this endpoint require authentication at all?" - whether one authenticated identity can access another's specific resource is what the IDOR module below checks instead.
   - **IDOR/BOLA** (opt-in, `sentinel.scan.idor.enabled=true`): needs two distinct identities to compare, supplied per-scan via `POST /api/scans`' `identities` field - every other module runs fully anonymous, so this is the only one that requires setup. When it sees a `POST` to a top-level collection (e.g. `/aquariums`), it creates a resource as identity A and reads the new id out of the JSON response; when it later sees a top-level item URL for that same collection (e.g. `/aquariums/{id}`), it substitutes the id A actually created and repeats the request as identity B. A 2xx response means B could access or modify a resource it doesn't own - reported as `IDOR` (CRITICAL for a mutating verb, HIGH otherwise); a 401/403/404 is the correct, secure outcome and produces no finding. v1 only implements this high-confidence, provable-ownership case (nested resources, e.g. `/aquariums/{id}/inhabitants/{inhabitantId}`, are out of scope - it's ambiguous which identity should be considered their owner), and stays silent for a collection whose create step wasn't observed in that same scan rather than guessing.
   - **BFLA** (opt-in, `sentinel.scan.bfla.enabled=true`): also needs at least one identity from `POST /api/scans`' `identities` field. Flags endpoints whose path suggests a privileged/administrative function - contains `admin`, `internal`, or `management` as a path segment - and checks whether a regular authenticated identity (A, falling back to B if A is unavailable) can still reach it. A 2xx response means the identity reached a function it likely shouldn't be able to - reported as `BFLA` (CRITICAL for a mutating verb, HIGH otherwise); a 401/403/404 is the correct, secure outcome and produces no finding. This is a heuristic, not a certainty: it has no notion of which functions are actually meant to be admin-only, so it can both miss privileged endpoints that don't match the keyword list and (rarely) flag one that's intentionally open to every authenticated user.
   - **Mass Assignment / BOPLA** (opt-in, `sentinel.scan.mass-assignment.enabled=true`): also needs at least one identity from `POST /api/scans`' `identities` field (identity A, falling back to B if A is unavailable) - a write endpoint has side effects, so unlike BFLA it never retries with the other identity on denial. On every discovered `POST`/`PUT`/`PATCH` endpoint that already has a generated JSON body sample, adds a small, fixed set of privilege/ownership-sounding field names (`role`, `isAdmin`, `ownerId`, `verified`) that aren't already one of that endpoint's own documented properties, then checks whether the response echoes any of them back with the exact value sent (searched regardless of response envelope, e.g. `{"data": {...}}`). A field echoed back means the server bound it straight onto the resource without the client ever being authorized to set it - reported as `MASS_ASSIGNMENT` (CRITICAL for `role`/`isAdmin` - direct privilege escalation; HIGH for `ownerId`/`verified` - data integrity/ownership); no echo, or a non-2xx response, produces no finding. Same caveat as BFLA: a heuristic on a short, conservative field list, not real insight into the target's actual model.
   - **JWT Weak Secret** (opt-in, `sentinel.scan.jwt-weak-secret.enabled=true`): needs an identity from `POST /api/scans`' `identities` field whose value actually looks like a JWT (three dot-separated base64url segments), not just any authenticated caller. Recomputes the token's own HMAC signature offline against a small, fixed dictionary of common/well-known secrets (`secret`, `changeme`, `password`, `your-256-bit-secret`, ...) - no request is ever sent to the target for this check. Each candidate is tried under two key-derivation conventions: the raw secret bytes used directly as the HMAC key (the most common case), and `SHA-256(secret)` (a real convention some frameworks use to guarantee a fixed-length key). Only applies to HMAC algorithms (`HS256`/`HS384`/`HS512`) declared in the token's own header - an RS/ES-signed token needs the issuer's private key, not a shared secret, so it's silently skipped. A match is reported as `WEAK_JWT_SECRET` (CRITICAL - anyone with the secret can forge a valid token for any user); identity A is tried first, identity B otherwise. Known, documented limitation: a target deriving its key some other way than the two tried here won't be caught even if the underlying secret is genuinely weak.
   - **Brute Force**: on any `POST` endpoint shaped like a login (a JSON body, or form/query parameters, with both a password-like and a username/email-like field), tries a short list of common/default credential pairs (`admin`/`admin`, `admin`/`password`, `root`/`root`, ...). If one is accepted, it's reported as `WEAK_CREDENTIALS` (CRITICAL). Independently, if the target never responds with 429 (Too Many Requests) or 423 (Locked) across the whole attempt budget, it's reported as `MISSING_BRUTE_FORCE_PROTECTION` (LOW) - worded cautiously, since a small fixed attempt count not tripping a lockout doesn't prove one doesn't exist at a higher threshold. Kept deliberately small and fixed (`sentinel.scan.brute-force.max-attempts`, default 8) rather than an exhaustive wordlist, to keep a scan fast and avoid hammering a real login endpoint.
   - **Security Misconfiguration**: three independent, read-only checks on every `GET` endpoint's ordinary successful response - no fuzzing, so it runs safely on write endpoints' `GET` counterparts too. (1) **Missing security headers**: flags a response lacking `X-Content-Type-Options`, `X-Frame-Options`, or `Content-Security-Policy` (plus `Strict-Transport-Security` when the target is HTTPS) as `MISSING_SECURITY_HEADERS` (LOW). (2) **Permissive CORS**: sends one extra request carrying a hostile `Origin` header; if the response reflects it back verbatim (or answers with a bare `*`) in `Access-Control-Allow-Origin`, it's `PERMISSIVE_CORS` - HIGH if paired with `Access-Control-Allow-Credentials: true` (a real, exploitable cross-origin credential leak), MEDIUM otherwise. (3) **Server banner disclosure**: flags a `Server` header containing a version number, or any `X-Powered-By` header at all, as `SERVER_BANNER_DISCLOSURE` (LOW) - both make it trivial for an attacker to look up known CVEs for that exact version.
   - **XSS**: fuzzes each discovered parameter with a handful of classic markers (`<script>alert('sentinel-xss')</script>` and variants) and checks whether the exact payload comes back unescaped in the response body - a plain substring match, reliable here because the markers are synthetic strings unlikely to appear in legitimate content. Unescaped reflection alone doesn't prove exploitability: a browser only executes it if the response is actually rendered as HTML, so the finding is split by how the response identifies itself. `Content-Type` missing or containing `html` means a browser could plausibly render the body directly - a real, exploitable `REFLECTED_XSS` (HIGH). Anything else (JSON, plain text, ...) - the common case for the JSON APIs this tool mostly targets, where `<script>` inside a JSON string value is inert - is downgraded to `UNSANITIZED_INPUT_REFLECTION` (LOW): a genuine missing-output-encoding defect, but not one this response alone turns into script execution.
   - **Excessive Data Exposure**: on every `GET` endpoint's ordinary successful response, recursively inspects the JSON body (objects and arrays, bounded depth) for a field whose *name* suggests it holds sensitive data - a small, fixed keyword list (`password`, `secret`, `privatekey`, `ssn`, `creditcard`, `cardnumber`, `cvv`), matched case- and separator-insensitively so `passwordHash`/`user_password`/etc. all match `password`. A match is reported as `EXCESSIVE_DATA_EXPOSURE` (CRITICAL for credential-type fields - `password`/`secret`/`privatekey` - HIGH for personal/financial ones); no fuzzing, no identity required, read-only by construction like Security Misconfiguration. The matched field's actual *value* is never included in the finding - only its name and JSON path - so a report from this module can't itself become a copy of the leaked data. A generic word like `token` is deliberately excluded from the keyword list: it matches far more legitimate fields (a pagination cursor, a CSRF token issued to the caller) than actual leaks, which would make the module noisy rather than useful.
   - **Actuator Exposure**: probes a small, fixed set of Spring Boot Actuator endpoint IDs (`env`, `heapdump`, `configprops`, `httpexchanges`, `beans`, `mappings`, `threaddump`, `loggers`) that disclose internal application state when reachable without authentication. Host-level, not per-endpoint - it runs once per scan (against the origin of whichever discovered endpoint it sees first) instead of once per endpoint. A plain GET per candidate path: a 2xx status paired with actuator-shaped content (JSON, the actuator vendor media type, or `application/octet-stream` for `heapdump`) is treated as exposed and reported as `EXPOSED_ACTUATOR_ENDPOINT` (CRITICAL for `env`/`heapdump` - direct credential/secret leakage; HIGH for `configprops`/`httpexchanges`; MEDIUM for `beans`/`mappings`/`threaddump`; LOW for `loggers`). The content-type check specifically guards against a false positive on a target that answers every unknown path with 200 (e.g. an SPA catch-all serving `index.html`). Response bodies are never included in a finding's evidence - only the probed path and its outcome.
   - **Rate Limit**: fires a burst of back-to-back requests (`sentinel.scan.rate-limit.burst-size`, default 130) at each `GET` endpoint and checks whether the target ever throttles (429/423). If it never does, reports `MISSING_RATE_LIMITING` (LOW), worded with the same caution as the brute-force protection check. The burst needs to exceed the target's actual rate-limit capacity to be a meaningful test - raise `sentinel.scan.rate-limit.burst-size` (or `SENTINEL_SCAN_RATE_LIMIT_BURST_SIZE` via `.env`) if you know or suspect it allows more than the default before throttling. `GET`-only and read-only by construction: bursting a state-changing verb would amplify its side effects far more than the one-off calls the other modules make. Ordered to run strictly last among all modules, since its deliberate burst can exhaust a shared per-IP rate-limit bucket that covers every route, not just the one being bursted.
   - **Sensitive File Exposure**: probes a small, fixed set of paths that have no business being reachable on a deployed web app - a checked-out `.git` directory (`.git/HEAD`, `.git/config`), environment files (`.env`, `.env.local`), a stray private key (`id_rsa`), and infrastructure/config backups (`docker-compose.yml`, `backup.sql`, `web.config`). Host-level like Actuator Exposure - runs once per scan, not once per endpoint. A plain GET per candidate path, gated on two independent signals: a 2xx status **and** the response body matching that file's own expected format (a git ref line, a `[core]` section, a PEM private-key marker, `services:` for a compose file, `CREATE TABLE`/`INSERT INTO` for a SQL dump, ...) - status alone would false-positive on a target that answers every unknown path with 200 (e.g. an SPA catch-all). A match is reported as `EXPOSED_SENSITIVE_FILE` (CRITICAL for `.git/*`, `.env*`, and `id_rsa` - direct source/credential/key exposure; HIGH for `docker-compose.yml`/`backup.sql`; MEDIUM for `web.config`). Response bodies are never included in a finding's evidence - only the probed path and its outcome.
   - **Rate Limit Bypass**: only meaningful once a rate limit has actually triggered - bursts a `GET` endpoint exactly like Rate Limit above until throttled (429/423), then repeats the same request once per candidate header (`X-Forwarded-For`, `X-Real-IP`, `X-Client-IP`, `True-Client-IP`) with a fresh, obviously-synthetic IP (the RFC 5737 `203.0.113.0/24` documentation range) as its value. A request that stops being throttled purely because of that header proves the rate-limit bucket is keyed by attacker-controlled input instead of the real client address - reported as `RATE_LIMIT_BYPASS` (HIGH). Never got throttled at all within the burst? Nothing to report here - that absence is `MISSING_RATE_LIMITING`'s job. Ordered to run immediately after Rate Limit for the same reason that module runs last: both deliberately burst a shared, per-IP bucket, so they need to run back-to-back at the very end rather than interleaved with single-request checks that would otherwise be starved of a clean response.
3. **Report**: JSON with every finding (endpoint, parameter, payload, evidence, recommendation, severity), a summary broken down **by severity and by issue type**, a numeric risk score alongside the qualitative rating, and a `narrative` field with a human-readable summary.

## Quick start

### From source

```bash
./mvnw spring-boot:run
```

The app starts on `http://localhost:8080`.

### With Docker, against an already-running "victim" app

If the victim already runs via its own `docker-compose`, Sentinel can join the same Docker network to reach it by container name instead of `localhost`:

```bash
cp env.example .env
# open .env and set VICTIM_NETWORK_NAME to the victim's real network name
# (find it with: docker network ls)
docker compose up -d --build
```

Sentinel will be reachable at `http://localhost:8088`. Details and troubleshooting are in the comments of `docker-compose.yml` and `env.example`. `src/` is bind-mounted into the container, so after a code change `docker compose restart sentinel` picks it up in a few seconds - no image rebuild needed (see `Dockerfile`). Defaults are deliberately conservative for repeated local iteration against the same victim: `GET`-only (`SENTINEL_SCAN_ALLOWED_HTTP_METHODS`) so re-running a scan never mutates its data, and `DEBUG` HTTP logging (`SENTINEL_LOG_HTTP_LEVEL`) for full visibility. Widen either in `.env` once you deliberately want to exercise write endpoints or quiet the logs down.

**Fully automatic scan (zero manual commands)**: if you also set `SENTINEL_SCAN_AUTO_TARGET_URL` in `.env` to the victim's URL (e.g. `http://api-gateway:8080`), Sentinel waits on its own for the target to respond and launches the scan on container startup, with no manual request needed. The result can be checked at any time with:

```bash
curl http://localhost:8088/api/scans/latest
```

## Using the API

**Start a scan**

```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "http://localhost:9090"}'
```

**Optional: two identities for the IDOR module**

```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "http://localhost:9090",
    "identities": {
      "a": { "header": "Authorization", "value": "Bearer <tokenForUserA>" },
      "b": { "header": "Authorization", "value": "Bearer <tokenForUserB>" }
    }
  }'
```

Sentinel never generates or discovers these tokens - supply two already valid for the target. Omit `identities` entirely (the default) for a fully anonymous scan, same as before; the IDOR module (also opt-in, `sentinel.scan.idor.enabled=true`) stays a no-op without both, and the BFLA and Mass Assignment modules (also opt-in, `sentinel.scan.bfla.enabled=true` / `sentinel.scan.mass-assignment.enabled=true`) stay no-ops without at least one.

Response (example):

```json
{
  "id": "…",
  "targetUrl": "http://localhost:9090",
  "endpointsDiscovered": 3,
  "endpointsTested": 3,
  "openApiSpecUrl": null,
  "findings": [ { "module": "sql-injection", "type": "SQL_INJECTION_ERROR_BASED", "description": "...", "recommendation": "...", "occurrences": [ { "severity": "CRITICAL", "endpointUrl": "...", "...": "..." } ] } ],
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

`findings` is a list of **groups**, not raw individual findings: every occurrence sharing the same `module` (`sql-injection`, `missing-authentication`, `brute-force`, `security-misconfiguration`, `xss`, `data-exposure`, `actuator-exposure`, `sensitive-file-exposure`, `rate-limit`, `rate-limit-bypass`, `idor`, `bfla`, `mass-assignment`, `jwt-weak-secret`), `type`, `description`, and `recommendation` collapses into one entry with an `occurrences` array - a scan flagging the same missing-rate-limiting issue on twenty endpoints produces one group with twenty occurrences instead of twenty near-identical objects repeating the same description and recommendation text. Each occurrence carries the fields that actually differ per endpoint: `id`, `severity`, `endpointUrl`, `method`, `parameter`, `payload`, `evidence`. Groups come out in the order their module ran; `summary.countsByType`/`countsBySeverity` still count every individual occurrence, not groups.

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
| `sentinel.scan.data-exposure.enabled` | `true` | Enables/disables the Excessive Data Exposure module |
| `sentinel.scan.actuator-exposure.enabled` | `true` | Enables/disables the Actuator Exposure module |
| `sentinel.scan.sensitive-file-exposure.enabled` | `true` | Enables/disables the Sensitive File Exposure module |
| `sentinel.scan.rate-limit.enabled` | `true` | Enables/disables the Rate Limit module |
| `sentinel.scan.rate-limit-bypass.enabled` | `true` | Enables/disables the Rate Limit Bypass module |
| `sentinel.scan.rate-limit.burst-size` | `130` | Number of back-to-back requests fired at each `GET` endpoint before concluding no throttling kicked in. Must exceed the target's real rate-limit capacity to be a meaningful test |
| `sentinel.scan.idor.enabled` | `false` | Enables the IDOR/BOLA module. Unlike every other module, it defaults to **disabled**: it's meaningless without the two identities supplied via `POST /api/scans`' `identities` field |
| `sentinel.scan.bfla.enabled` | `false` | Enables the BFLA module. Also defaults to **disabled**: it's meaningless without at least one identity supplied via `POST /api/scans`' `identities` field |
| `sentinel.scan.mass-assignment.enabled` | `false` | Enables the Mass Assignment / BOPLA module. Also defaults to **disabled**: it's meaningless without at least one identity supplied via `POST /api/scans`' `identities` field |
| `sentinel.scan.jwt-weak-secret.enabled` | `false` | Enables the JWT Weak Secret module. Also defaults to **disabled**: it's meaningless without an identity whose value is actually a JWT |

Every future attack module will follow the same `sentinel.scan.<module>.enabled` convention.

## Risk metric

Besides the list of findings, `summary` answers three different questions:

- **`countsBySeverity` / `overallRisk`** - how bad is the worst problem found (INFO → CRITICAL).
- **`countsByType`** - how many problems for each issue type (`SQL_INJECTION_ERROR_BASED`, `SQL_INJECTION_BOOLEAN_BASED`, `MISSING_AUTHENTICATION`, `WEAK_CREDENTIALS`, `MISSING_BRUTE_FORCE_PROTECTION`, `MISSING_SECURITY_HEADERS`, `PERMISSIVE_CORS`, `SERVER_BANNER_DISCLOSURE`, `REFLECTED_XSS`, `UNSANITIZED_INPUT_REFLECTION`, `MISSING_RATE_LIMITING`, `IDOR`, `BFLA`, `MASS_ASSIGNMENT`, `EXCESSIVE_DATA_EXPOSURE`, `EXPOSED_ACTUATOR_ENDPOINT`, `EXPOSED_SENSITIVE_FILE`, `WEAK_JWT_SECRET`, `RATE_LIMIT_BYPASS`, ...), useful once more than one module is active and you want to know what to focus on.
- **`riskScore`** - a numeric score (weighted sum: CRITICAL=40, HIGH=20, MEDIUM=8, LOW=3, INFO=0) that distinguishes the *volume* of problems at equal `overallRisk`: 1 CRITICAL and 20 CRITICAL share the same `overallRisk`, but a very different score. It's a heuristic meant for comparing successive scans of the same target, not a CVSS or an "official" score.

## Development

```bash
./mvnw test   # runs the whole suite
```

## Stack

Java 17, Spring Boot, Jsoup (HTML parsing), Jackson (OpenAPI parsing). Scans run synchronously; reports are kept in memory for retrieval by id during the app's lifetime, and are also persisted as JSON files under `reports/` (see [Using the API](#using-the-api)).
