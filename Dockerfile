# Runs the app straight from source via Maven instead of a build-a-jar-then-copy-it multi-stage
# flow. Dependencies are resolved once and cached in an image layer; source is bind-mounted by
# docker-compose.yml, so picking up a code change only needs `docker compose restart sentinel`
# (a few seconds) instead of a full image rebuild. Not live class-reload - just skips the
# rebuild-the-image step a packaged jar would require.
FROM maven:3.9-eclipse-temurin-17
WORKDIR /app
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src src
EXPOSE 8080
ENTRYPOINT ["mvn", "-q", "spring-boot:run"]
