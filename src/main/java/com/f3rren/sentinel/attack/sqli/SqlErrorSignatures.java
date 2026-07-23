package com.f3rren.sentinel.attack.sqli;

import java.util.List;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Regex fingerprints for database error messages leaking through an application's response.
 * Presence of one of these strings in a response that only appears after an SQL-breaking
 * payload is strong evidence of an error-based SQL injection.
 */
final class SqlErrorSignatures {

    record Signature(String database, Pattern pattern) {
    }

    record MatchResult(String database, String snippet) {
    }

    private static final List<Signature> SIGNATURES = List.of(
            sig("MySQL/MariaDB", "SQL syntax.{0,100}MySQL"),
            sig("MySQL/MariaDB", "Warning.{0,20}\\bmysqli?_"),
            sig("MySQL/MariaDB", "valid MySQL result"),
            sig("MySQL/MariaDB", "check the manual that corresponds to your (MySQL|MariaDB) server version"),
            sig("PostgreSQL", "PostgreSQL.{0,100}ERROR"),
            sig("PostgreSQL", "PSQLException"),
            sig("PostgreSQL", "pg_query\\(\\)"),
            sig("MSSQL", "Unclosed quotation mark after the character string"),
            sig("MSSQL", "Microsoft SQL Server"),
            sig("MSSQL", "System\\.Data\\.SqlClient"),
            sig("Oracle", "ORA-\\d{5}"),
            sig("SQLite", "SQLite/JDBCDriver"),
            sig("SQLite", "SQLITE_ERROR"),
            sig("SQLite", "sqlite3\\.OperationalError"),
            sig("JDBC", "java\\.sql\\.SQLException"),
            sig("Hibernate/JPA", "org\\.hibernate\\.exception"),
            sig("Generic", "SQL syntax.{0,50}error"),
            sig("Generic", "unterminated quoted string")
    );

    private SqlErrorSignatures() {
    }

    private static Signature sig(String database, String regex) {
        return new Signature(database, Pattern.compile(regex, Pattern.CASE_INSENSITIVE));
    }

    static Optional<MatchResult> find(String body) {
        if (body == null || body.isBlank()) {
            return Optional.empty();
        }
        for (Signature signature : SIGNATURES) {
            Matcher matcher = signature.pattern().matcher(body);
            if (matcher.find()) {
                int start = Math.max(0, matcher.start() - 40);
                int end = Math.min(body.length(), matcher.end() + 80);
                String snippet = body.substring(start, end).replaceAll("\\s+", " ").trim();
                return Optional.of(new MatchResult(signature.database(), snippet));
            }
        }
        return Optional.empty();
    }
}
