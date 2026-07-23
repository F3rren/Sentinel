package com.f3rren.sentinel.attack.sqli;

import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

class SqlErrorSignaturesTest {

    @Test
    void detectsMySqlErrorMessage() {
        String body = "<html><body>Warning: mysqli_fetch_array() expects parameter 1... "
                + "You have an error in your SQL syntax; check the manual that corresponds "
                + "to your MySQL server version</body></html>";

        Optional<SqlErrorSignatures.MatchResult> match = SqlErrorSignatures.find(body);

        assertThat(match).isPresent();
        assertThat(match.get().database()).isEqualTo("MySQL/MariaDB");
    }

    @Test
    void detectsPostgresException() {
        String body = "Internal Server Error: org.postgresql.util.PSQLException: ERROR: syntax error at or near \"'\"";

        Optional<SqlErrorSignatures.MatchResult> match = SqlErrorSignatures.find(body);

        assertThat(match).isPresent();
        assertThat(match.get().database()).isEqualTo("PostgreSQL");
    }

    @Test
    void returnsEmptyForBenignBody() {
        String body = "<html><body><h1>Welcome</h1><p>Everything is fine.</p></body></html>";

        assertThat(SqlErrorSignatures.find(body)).isEmpty();
    }

    @Test
    void returnsEmptyForBlankBody() {
        assertThat(SqlErrorSignatures.find("")).isEmpty();
        assertThat(SqlErrorSignatures.find(null)).isEmpty();
    }
}
