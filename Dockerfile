# Multi-stage, self-contained build. The first stage compiles the app into a runnable Spring
# Boot jar in a full Maven/JDK image; the second copies only that jar into a slim JRE runtime.
# The result carries no Maven, no build tools and no source at runtime, so it can be published
# to a registry and run anywhere with `docker run` - it does not depend on the source tree being
# present (unlike a `mvn spring-boot:run`-from-source image would).
#
# Dependencies are resolved in their own layer (before the source is copied) so an unchanged
# pom.xml keeps that layer cached across source-only rebuilds.
FROM maven:3.9-eclipse-temurin-17 AS build
WORKDIR /app
COPY pom.xml .
RUN mvn -q -B dependency:go-offline
COPY src src
RUN mvn -q -B clean package -DskipTests

FROM eclipse-temurin:17-jre
WORKDIR /app
# Only the executable jar is matched here - the plain `*.jar.original` Spring Boot leaves behind
# ends in `.original`, not `.jar`, so this glob resolves to the single runnable artifact.
COPY --from=build /app/target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
