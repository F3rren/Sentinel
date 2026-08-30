# Sentinel

[![CI](https://github.com/F3rren/Sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/F3rren/Sentinel/actions/workflows/ci.yml)

Sentinel is an **automated security testing** tool: given an application's address (e.g. `localhost:8080`), it discovers the exposed endpoints and launches automated attacks to find vulnerabilities, returning a report with severity and remediation guidance.

## ⚠️ Disclaimer — read before using

**Sentinel is an offensive security tool. It actively attacks whatever target you point it at, and it can be pointed at any host reachable over the network.** Use it with extreme caution.

- **Authorized use only.** Run it exclusively against systems you own or for which you hold explicit, written authorization to perform security testing (your own projects, a staging environment, an in-scope penetration-testing engagement, a CTF you are entered in). Scanning, probing, or attacking systems without the owner's permission is illegal in most jurisdictions and may constitute a criminal offense.
- **You are solely responsible.** By running Sentinel you accept full and sole responsibility for how, and against what, you use it. Any consequence of its use — including but not limited to service disruption, data loss or corruption, resource exhaustion, account lockouts, triggered defenses, financial cost, or legal liability — is **attributable entirely to you, the person operating the tool, and never to its authors, contributors, or distributors.**
- **Legal compliance.** You represent and warrant that you are aware of and will comply with all applicable laws and regulations in your jurisdiction regarding security testing, computer access, and data protection (including GDPR if applicable). It is your responsibility to determine whether your use of Sentinel is lawful where you are located. Use of this software may be subject to export control regulations (EU Dual-Use Regulation 2021/821).
- **Indemnification.** You agree to indemnify, defend, and hold harmless the authors, contributors, and distributors of Sentinel from any and all claims, liabilities, damages, losses, costs, or expenses (including reasonable legal fees) arising from your use of this software, including any use that violates applicable laws or third-party rights.
- **No warranty, no liability.** The software is provided "as is", without warranty of any kind, express or implied. To the maximum extent permitted by applicable law, the authors and contributors shall not be liable for any claim, damage, or other liability arising from, out of, or in connection with the software or its use. If you do not accept these terms, do not use the software.

**By downloading, installing, or using Sentinel, you acknowledge that you have read, understood, and agree to be bound by these terms.**


By default Sentinel attacks only read-only (`GET`) endpoints so a scan cannot mutate a target's data; enabling write methods (`POST`/`PUT`/`PATCH`/`DELETE`) is a deliberate, opt-in choice whose consequences are yours alone.

## What it does today

1. **Endpoint discovery**, in two phases: **OpenAPI/Swagger** (preferred) - reads a spec at `/v3/api-docs` or similar, follows gateway aggregation across multiple services, and generates a type-aware JSON request body from the schema so write endpoints get a real, processable request instead of an immediate 415/400. **HTML crawling** - a fallback/supplement that parses links with a query string and forms.

2. **Attack**, fifteen modules:

   | Module | Findings (severity) | Default |
   |---|---|---|
   | SQL Injection | `SQL_INJECTION_ERROR_BASED` (CRITICAL), `SQL_INJECTION_BOOLEAN_BASED` (HIGH) | opt-out |
   | Missing Authentication | `MISSING_AUTHENTICATION` (HIGH mutating / MEDIUM otherwise) | opt-out |
   | Brute Force | `WEAK_CREDENTIALS` (CRITICAL), `MISSING_BRUTE_FORCE_PROTECTION` (LOW) | opt-out |
   | Security Misconfiguration | `MISSING_SECURITY_HEADERS` (LOW), `PERMISSIVE_CORS` (MEDIUM/HIGH), `SERVER_BANNER_DISCLOSURE` (LOW) | opt-out |
   | XSS | `REFLECTED_XSS` (HIGH), `UNSANITIZED_INPUT_REFLECTION` (LOW) | opt-out |
   | Excessive Data Exposure | `EXCESSIVE_DATA_EXPOSURE` (CRITICAL/HIGH) | opt-out |
   | Verbose Error Disclosure | `VERBOSE_ERROR_DISCLOSURE` (HIGH/MEDIUM) | opt-out |
   | Actuator Exposure | `EXPOSED_ACTUATOR_ENDPOINT` (CRITICAL → LOW, by endpoint ID) | opt-out |
   | Sensitive File Exposure | `EXPOSED_SENSITIVE_FILE` (CRITICAL/HIGH/MEDIUM, by file) | opt-out |
   | Rate Limit | `MISSING_RATE_LIMITING` (LOW) | opt-out |
   | Rate Limit Bypass | `RATE_LIMIT_BYPASS` (HIGH) | opt-out |
   | IDOR/BOLA | `IDOR` (CRITICAL mutating / HIGH otherwise) | opt-in - needs 2 identities |
   | BFLA | `BFLA` (CRITICAL mutating / HIGH otherwise) | opt-in - needs 1+ identity |
   | Mass Assignment / BOPLA | `MASS_ASSIGNMENT` (CRITICAL/HIGH) | opt-in - needs 1+ identity |
   | JWT Weak Secret | `WEAK_JWT_SECRET` (CRITICAL) | opt-in - needs a JWT identity |

   Everything above runs fully anonymous by default; the four opt-in modules need at least one caller identity supplied via `POST /api/scans`'s `identities` field (see [Using the API](#using-the-api)). Every module can be toggled independently with `sentinel.scan.<module>.enabled` (see [Configuration](#configuration)). Each finding carries a severity, the exact evidence that triggered it, and a remediation recommendation; the specific detection mechanics, heuristics, and edge cases for each module are documented in its own class' Javadoc under `src/main/java/com/f3rren/sentinel/attack/`.

3. **Report**: JSON with every finding (endpoint, parameter, payload, evidence, recommendation, severity), a summary broken down **by severity and by issue type**, a numeric risk score alongside the qualitative rating, and a `narrative` field with a human-readable summary. Also available as **SARIF** for GitHub code scanning, and with a **fail-on gate** for pipelines (see [CI/CD integration](#cicd-integration)).

## Quick start

### From source

```bash
./mvnw spring-boot:run
```

The app starts on `http://localhost:8080`.

### With Docker

The published image is self-contained - no source checkout, no Maven, no build step:

```bash
docker run --rm -p 8088:8080 ghcr.io/f3rren/sentinel:latest
# pin a release instead of latest: ghcr.io/f3rren/sentinel:1.0.0
```

Sentinel is then reachable at `http://localhost:8088`. There are two Compose files for the two networking situations:

**a) Standalone / any target by URL** (`docker-compose.standalone.yml`) - the general case: scan a public host, a remote IP, or a port mapped on your own machine, without needing the target's Docker network to exist.

```bash
docker compose -f docker-compose.standalone.yml up -d
curl -X POST http://localhost:8088/api/scans \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "https://target.example.com"}'
```

To reach a service on a port mapped to your own machine, use `host.docker.internal` as the host (e.g. `{"targetUrl": "http://host.docker.internal:9090"}`).

**b) Same Docker host as the victim** (`docker-compose.yml`) - when the victim runs via its own `docker-compose` and you want to reach it by container name: Sentinel joins the victim's Docker network.

```bash
cp .env.example .env
# set VICTIM_NETWORK_NAME to the victim's real network name (docker network ls)
docker compose up -d --build
```

Both files default to the published image (`SENTINEL_VERSION` pins a release) and fall back to a local build with `--build`. Defaults are conservative: `GET`-only (`SENTINEL_SCAN_ALLOWED_HTTP_METHODS`) so a scan never mutates data. Details and troubleshooting are in each file's comments and `.env.example`.

**Fully automatic scan**: set `SENTINEL_SCAN_AUTO_TARGET_URL` (in `.env` or the environment) to the target's URL and Sentinel scans it on its own once reachable, no manual request needed:

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

**Optional: identities for the opt-in modules**

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

Sentinel never generates or discovers these tokens - supply ones already valid for the target. IDOR needs both `a` and `b`; BFLA, Mass Assignment, and JWT Weak Secret need only one (`a`, falling back to `b`).

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

`findings` is a list of **groups**: every occurrence sharing the same module, type, description, and recommendation collapses into one entry with an `occurrences` array, rather than repeating the same description/recommendation text per endpoint. Each occurrence carries what actually differs: `id`, `severity`, `endpointUrl`, `method`, `parameter`, `payload`, `evidence`. `summary.countsByType`/`countsBySeverity` count every individual occurrence, not groups.

**`summary.possiblyRateLimited`**: a module fuzzing many parameters can by itself trip the target's rate limiter, making later results look clean when they were actually just throttled. Once at least 10 requests were made and 15%+ came back throttled, this flag is set and the `narrative` gets a `WARNING:` caveat - read such a report as "clean among what responded normally," not a clean bill of health.

**Retrieve a previously generated report**

```bash
curl http://localhost:8080/api/scans/{id}
curl http://localhost:8080/api/scans/latest   # the most recent one, manual or automatic
```

**On file**: every completed scan is also saved in `reports/` (configurable via `sentinel.scan.reports-directory`), named `<timestamp>-<host>-<scanId>` with both a `.json` and a `.sarif` extension. With Docker, the folder is mounted to `./reports` on the host, so files survive `docker compose down`.

## CI/CD integration

Sentinel can run as a step in a pipeline, in two complementary ways.

**SARIF output** — every report is also available as [SARIF 2.1.0](https://sarifweb.azurewebsites.net/), the format GitHub code scanning ingests: uploaded to a repository, the findings show up in its **Security** tab, bucketed by severity and de-duplicated across runs. Get it from the API or the file written alongside the JSON:

```bash
curl http://localhost:8088/api/scans/latest/sarif   # or /api/scans/{id}/sarif
# also written to reports/<...>.sarif on every scan
```

**Fail-on gate** — set `SENTINEL_SCAN_FAIL_ON` to a severity and the startup auto-scan becomes one-shot: the container exits `0` if no finding reached that severity, or `1` if one did (fails closed - exit `1` - if the scan can't even run). The report files are written before the exit, so the pipeline can still collect them. This turns Sentinel into a security gate that fails the build on findings.

Example GitHub Actions job that scans a deployed target, fails on any HIGH-or-worse finding, and uploads the SARIF to code scanning:

```yaml
- name: Security scan (Sentinel)
  run: |
    docker run --rm \
      -e SENTINEL_SCAN_AUTO_TARGET_URL=https://staging.example.com \
      -e SENTINEL_SCAN_FAIL_ON=HIGH \
      -v ${{ github.workspace }}/reports:/app/reports \
      ghcr.io/f3rren/sentinel:latest
- name: Upload SARIF
  if: always()   # upload even when the gate failed the step above
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: reports
```

## Configuration

Properties in `src/main/resources/application.properties` (overridable via environment variable, e.g. `SENTINEL_SCAN_MAX_ENDPOINTS`):

| Property | Default | Description |
|---|---|---|
| `sentinel.scan.user-agent` | `Sentinel-Scanner/0.1 (+authorized-security-testing)` | User-Agent used on every request to the target |
| `sentinel.scan.request-timeout-ms` | `8000` | Timeout for a single HTTP request |
| `sentinel.scan.connect-timeout-ms` | `5000` | Connection timeout |
| `sentinel.scan.max-endpoints` | `25` | Maximum number of endpoints attacked per scan |
| `sentinel.scan.reports-directory` | `reports` | Folder where every report is also saved as a JSON file. Empty to disable file persistence |
| `sentinel.scan.allowed-http-methods` | `GET,POST,PUT,PATCH,DELETE` | Only endpoints with these methods get attacked. E.g. `GET` for a scan that never writes |
| `sentinel.scan.base-path` | _(empty)_ | Common API prefix on the target (e.g. `/api`). Used by the IDOR module so `/api/x/{id}` resources are recognized as top-level collection/item pairs. Empty = API at the root |
| `sentinel.scan.auto-target-url` | _(empty)_ | If set, an automatic scan runs against this URL on startup |
| `sentinel.scan.auto-scan-max-attempts` | `20` | Reachability attempts against the target before giving up on the auto-scan |
| `sentinel.scan.auto-scan-retry-delay-ms` | `3000` | Wait between one attempt and the next |
| `sentinel.scan.fail-on` | _(empty / off)_ | CI gate: a severity (`INFO`/`LOW`/`MEDIUM`/`HIGH`/`CRITICAL`) that makes the auto-scan exit non-zero on findings at or above it. Empty keeps the app running. Applies only with `auto-target-url` set |
| `sentinel.scan.<module>.enabled` | `true` (`false` for the 4 opt-in modules) | Per-module on/off switch - see the module table above for names |
| `sentinel.scan.brute-force.max-attempts` | `8` | Credential pairs tried per login-shaped endpoint |
| `sentinel.scan.rate-limit.burst-size` | `130` | Requests fired at each `GET` endpoint before concluding no throttling kicked in - must exceed the target's real capacity to be meaningful |

Module property names follow the table: `sql-injection`, `missing-authentication`, `brute-force`, `security-misconfiguration`, `xss`, `data-exposure`, `verbose-error-disclosure`, `actuator-exposure`, `sensitive-file-exposure`, `rate-limit`, `rate-limit-bypass`, `idor`, `bfla`, `mass-assignment`, `jwt-weak-secret`.

## Risk metric

Besides the list of findings, `summary` answers three questions:

- **`countsBySeverity` / `overallRisk`** - how bad is the worst problem found (INFO → CRITICAL).
- **`countsByType`** - how many problems per issue type (one `VulnerabilityType` per module row in the table above), useful once several modules are active.
- **`riskScore`** - a weighted sum (CRITICAL=40, HIGH=20, MEDIUM=8, LOW=3, INFO=0) that distinguishes *volume* at equal `overallRisk` (1 vs. 20 CRITICAL findings share a rating but not a score). A heuristic for comparing successive scans of the same target, not a CVSS or "official" score.

## Development

```bash
./mvnw test   # runs the whole suite
```

## Stack

Java 17, Spring Boot, Jsoup (HTML parsing), Jackson (OpenAPI parsing). Scans run synchronously; reports are kept in memory for retrieval by id during the app's lifetime, and are also persisted as JSON files under `reports/` (see [Using the API](#using-the-api)).
