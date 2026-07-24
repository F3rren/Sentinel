# Sentinel

Sentinel è uno strumento di **automated security testing**: dato l'indirizzo di un'applicazione (es. `localhost:8080`), scopre gli endpoint esposti e lancia attacchi automatici per individuare vulnerabilità, restituendo un report con gravità e raccomandazioni di remediation.

> **Uso previsto**: solo su applicazioni di cui hai l'autorizzazione a testare la sicurezza (i tuoi progetti, ambienti di staging, target di un pentest autorizzato). Non puntarlo su sistemi di terzi senza consenso esplicito.

## Cosa fa oggi

1. **Discovery degli endpoint**, in due fasi:
   - **OpenAPI/Swagger** (fase preferita): prova a leggere una spec su `/v3/api-docs`, `/v2/api-docs`, `/swagger.json`, `/openapi.json`, ecc. Se il target è un API gateway che aggrega più servizi (springdoc `swagger-config` o springfox `swagger-resources`), segue l'aggregazione e recupera le spec di tutti i servizi a valle.
   - **Crawling HTML**: se non trova una spec (o in aggiunta ad essa), analizza la pagina del target per link con query string e form, e li unisce (senza duplicati) agli endpoint trovati via Swagger.
2. **Attacco**: al momento è implementato un solo modulo — **SQL Injection**, sia error-based (fingerprint dei messaggi di errore di MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, SQLite, JDBC/Hibernate) sia boolean-based/blind (euristica su condizioni vero/falso iniettate).
3. **Report**: JSON con ogni finding (endpoint, parametro, payload, evidenza, raccomandazione, severità), un riepilogo per severità con rischio complessivo, e un campo `narrative` con un riassunto testuale in italiano.

Moduli pianificati per iterazioni successive: XSS, brute force sugli endpoint di autenticazione.

## Avvio rapido

### Da sorgente

```bash
./mvnw spring-boot:run
```

L'app parte su `http://localhost:8080`.

### Con Docker, contro un'app "vittima" già in esecuzione

Se la vittima gira già tramite un suo `docker-compose`, Sentinel può agganciarsi alla stessa rete Docker per raggiungerla via nome del container invece che `localhost`:

```bash
cp .env.example .env
# apri .env e imposta VICTIM_NETWORK_NAME con il nome reale della rete della vittima
# (si trova con: docker network ls)
docker compose up -d --build
```

Sentinel sarà raggiungibile su `http://localhost:8088`. Dettagli e troubleshooting sono nei commenti di `docker-compose.yml` e `.env.example`.

## Uso dell'API

**Avviare una scansione**

```bash
curl -X POST http://localhost:8080/api/scans \
  -H "Content-Type: application/json" \
  -d '{"targetUrl": "http://localhost:9090"}'
```

Risposta (esempio):

```json
{
  "id": "…",
  "targetUrl": "http://localhost:9090",
  "endpointsDiscovered": 3,
  "openApiSpecUrl": null,
  "findings": [ { "type": "SQL_INJECTION_ERROR_BASED", "severity": "CRITICAL", "...": "..." } ],
  "summary": { "totalFindings": 1, "overallRisk": "CRITICAL", "countsBySeverity": { "...": 0 } },
  "narrative": "Investigazione su http://localhost:9090 completata in ... Rilevate 1 vulnerabilità ..."
}
```

**Recuperare un report già generato**

```bash
curl http://localhost:8080/api/scans/{id}
```

## Configurazione

Proprietà in `src/main/resources/application.properties` (sovrascrivibili anche da variabile d'ambiente, es. `SENTINEL_SCAN_MAX_ENDPOINTS`):

| Proprietà | Default | Descrizione |
|---|---|---|
| `sentinel.scan.user-agent` | `Sentinel-Scanner/0.1 (+authorized-security-testing)` | User-Agent usato in ogni richiesta verso il target |
| `sentinel.scan.request-timeout-ms` | `8000` | Timeout per singola richiesta HTTP |
| `sentinel.scan.connect-timeout-ms` | `5000` | Timeout di connessione |
| `sentinel.scan.max-endpoints` | `25` | Numero massimo di endpoint testati per scansione |

## Sviluppo

```bash
./mvnw test   # esegue l'intera suite
```

## Stack

Java 17, Spring Boot, Jsoup (parsing HTML), Jackson (parsing OpenAPI). Le scansioni sono sincrone e i report sono tenuti in memoria (nessuna persistenza al momento).
