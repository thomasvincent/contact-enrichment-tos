# syntax=docker/dockerfile:1.7

# --- Build stage ---
FROM maven:3.9.12-eclipse-temurin-21 AS build
WORKDIR /workspace

# Cache dependencies first
COPY implementations/java/pom.xml ./pom.xml
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -e -ntp -DskipTests -P local-fast dependency:go-offline

# Copy sources and build
COPY implementations/java/src ./src
RUN --mount=type=cache,target=/root/.m2 \
    mvn -B -e -ntp -DskipTests -P local-fast package

# --- Runtime stage ---
FROM eclipse-temurin:21-jre
WORKDIR /app

# Copy bootable jar from build stage
COPY --from=build /workspace/target/contact-enrichment-tos-*.jar /app/app.jar

# Minimal runtime env (override with orchestrator)
ENV SPRING_PROFILES_ACTIVE=dev \
    SERVER_PORT=8080

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=3s --retries=10 \
  CMD curl -fsS http://localhost:8080/api/v1/health || exit 1

ENTRYPOINT ["java","-jar","/app/app.jar"]
