# Sentinel

Sentinel è uno strumento di **automated security testing**: dato l'indirizzo di un'applicazione (es. `localhost:8080`), scopre gli endpoint esposti e lancia attacchi automatici per individuare vulnerabilità, restituendo un report con gravità e raccomandazioni di remediation.

> **Uso previsto**: solo su applicazioni di cui hai l'autorizzazione a testare la sicurezza (i tuoi progetti, ambienti di staging, target di un pentest autorizzato). Non puntarlo su sistemi di terzi senza consenso esplicito.

## Cosa fa oggi

1. **Discovery degli endpoint**, in due fasi:
   - **OpenAPI/Swagger** (fase preferita): prova a leggere una spec su `/v3/api-docs`, `/v2/api-docs`, `/swagger.json`, `/openapi.json`, ecc. Se il target è un API gateway che aggrega più servizi (springdoc `swagger-config` o springfox `swagger-resources`), segue l'aggregazione e recupera le spec di tutti i servizi a valle. Quando un'operazione documenta un `requestBody` JSON (tipico di POST/PUT/PATCH), ne genera anche un body di esempio type-aware (risolvendo i `$ref` verso `components/schemas`: interi come numeri, booleani come booleani, stringhe con formato coerente), così l'endpoint riceve una richiesta che può effettivamente elaborare invece di respingerla subito con 415/400 per un body mancante o nel formato sbagliato.
   - **Crawling HTML**: se non trova una spec (o in aggiunta ad essa), analizza la pagina del target per link con query string e form, e li unisce (senza duplicati) agli endpoint trovati via Swagger.
2. **Attacco**, due moduli:
   - **SQL Injection**: sia error-based (fingerprint dei messaggi di errore di MySQL/MariaDB, PostgreSQL, MSSQL, Oracle, SQLite, JDBC/Hibernate) sia boolean-based/blind (euristica su condizioni vero/falso iniettate).
   - **Missing Authentication**: segnala gli endpoint che rispondono con successo (2xx) a una richiesta priva di qualunque credenziale (Sentinel non invia mai header di autenticazione). Una risposta 401/403 è considerata prova che l'autenticazione è applicata (nessun finding); qualunque altro status (400/404/5xx) è inconclusivo e viene ignorato. Grazie al body JSON generato dallo schema OpenAPI, questo vale ora anche per endpoint POST/PUT/PATCH che richiedono un body — prima restituivano quasi sempre 415 (inconclusivo), ora possono ricevere una risposta reale. È volutamente più limitato di un vero test IDOR/BOLA (che richiederebbe due identità autenticate distinte da confrontare, concetto che Sentinel non ha ancora): risponde solo alla domanda "questo endpoint richiede autenticazione?".
3. **Report**: JSON con ogni finding (endpoint, parametro, payload, evidenza, raccomandazione, severità), un riepilogo per severità **e per tipologia di problema**, un punteggio di rischio numerico oltre alla valutazione qualitativa, e un campo `narrative` con un riassunto testuale in italiano.

Moduli pianificati per iterazioni successive: XSS, IDOR/BOLA con identità multiple, brute force sugli endpoint di autenticazione.

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

**Scansione completamente automatica (zero comandi manuali)**: se in `.env` valorizzi anche `SENTINEL_SCAN_AUTO_TARGET_URL` con l'URL della vittima (es. `http://api-gateway:8080`), Sentinel attende da solo che il target risponda e lancia la scansione all'avvio del container, senza bisogno di alcuna richiesta manuale. Il risultato è consultabile in qualsiasi momento con:

```bash
curl http://localhost:8088/api/scans/latest
```

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
  "endpointsTested": 3,
  "openApiSpecUrl": null,
  "findings": [ { "type": "SQL_INJECTION_ERROR_BASED", "severity": "CRITICAL", "...": "..." } ],
  "summary": {
    "totalFindings": 1,
    "overallRisk": "CRITICAL",
    "riskScore": 40,
    "countsBySeverity": { "...": 0 },
    "countsByType": { "SQL_INJECTION_ERROR_BASED": 1, "SQL_INJECTION_BOOLEAN_BASED": 0, "MISSING_AUTHENTICATION": 0 }
  },
  "narrative": "Investigazione su http://localhost:9090 completata in ... Rilevate 1 vulnerabilità (rischio complessivo: CRITICAL, punteggio di rischio: 40): 1 CRITICAL. Per tipologia: 1 SQL_INJECTION_ERROR_BASED."
}
```

**Recuperare un report già generato**

```bash
curl http://localhost:8080/api/scans/{id}
curl http://localhost:8080/api/scans/latest   # l'ultimo eseguito, manuale o automatico
```

**Su file**: ogni scansione completata viene anche salvata come JSON in `reports/` (dentro il progetto, configurabile con `sentinel.scan.reports-directory`), con nome `<timestamp>-<host>-<scanId>.json` — utile per conservare, confrontare o versionare i risultati senza dover interrogare l'API. Con Docker la cartella è montata su `./reports` nell'host (vedi `docker-compose.yml`), quindi i file restano anche dopo `docker compose down`.

## Configurazione

Proprietà in `src/main/resources/application.properties` (sovrascrivibili anche da variabile d'ambiente, es. `SENTINEL_SCAN_MAX_ENDPOINTS`):

| Proprietà | Default | Descrizione |
|---|---|---|
| `sentinel.scan.user-agent` | `Sentinel-Scanner/0.1 (+authorized-security-testing)` | User-Agent usato in ogni richiesta verso il target |
| `sentinel.scan.request-timeout-ms` | `8000` | Timeout per singola richiesta HTTP |
| `sentinel.scan.connect-timeout-ms` | `5000` | Timeout di connessione |
| `sentinel.scan.max-endpoints` | `25` | Numero massimo di endpoint testati per scansione |
| `sentinel.scan.reports-directory` | `reports` | Cartella dove ogni report viene salvato anche come file JSON. Vuoto per disabilitare il salvataggio su file |
| `sentinel.scan.allowed-http-methods` | `GET,POST,PUT,PATCH,DELETE` | Solo gli endpoint con questi metodi vengono attaccati (la discovery li trova comunque tutti). Es. `GET` per garantire una scansione che non tocca mai nulla in scrittura |
| `sentinel.scan.auto-target-url` | _(vuoto)_ | Se impostata, scansione automatica all'avvio su questo URL, zero comandi manuali |
| `sentinel.scan.auto-scan-max-attempts` | `20` | Tentativi di raggiungibilità del target prima di rinunciare all'auto-scan |
| `sentinel.scan.auto-scan-retry-delay-ms` | `3000` | Attesa tra un tentativo e l'altro |
| `sentinel.scan.sql-injection.enabled` | `true` | Abilita/disabilita il modulo SQL injection. A `false` il modulo non viene nemmeno istanziato |
| `sentinel.scan.missing-authentication.enabled` | `true` | Abilita/disabilita il modulo Missing Authentication |

Ogni modulo di attacco futuro (XSS, IDOR/BOLA, brute force, ...) seguirà la stessa convenzione `sentinel.scan.<modulo>.enabled`.

## Metrica di rischio

Oltre alla lista dei finding, `summary` risponde a tre domande diverse:

- **`countsBySeverity` / `overallRisk`** — quanto è grave il problema peggiore trovato (INFO → CRITICAL).
- **`countsByType`** — quanti problemi per ciascuna tipologia (`SQL_INJECTION_ERROR_BASED`, `SQL_INJECTION_BOOLEAN_BASED`, `MISSING_AUTHENTICATION`, ...), utile quando i moduli attivi sono più di uno e si vuole capire su cosa concentrarsi.
- **`riskScore`** — punteggio numerico (somma pesata: CRITICAL=40, HIGH=20, MEDIUM=8, LOW=3, INFO=0) che distingue il *volume* dei problemi a parità di `overallRisk`: 1 CRITICAL e 20 CRITICAL hanno lo stesso `overallRisk`, ma punteggio molto diverso. È una euristica pensata per confrontare scansioni successive dello stesso target, non un CVSS o un punteggio "ufficiale".

## Sviluppo

```bash
./mvnw test   # esegue l'intera suite
```

## Stack

Java 17, Spring Boot, Jsoup (parsing HTML), Jackson (parsing OpenAPI). Le scansioni sono sincrone e i report sono tenuti in memoria (nessuna persistenza al momento).
