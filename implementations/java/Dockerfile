# syntax=docker/dockerfile:1.7

# --- Build stage ---
FROM maven:3.9.12-eclipse-temurin-21 AS build
WORKDIR /workspace

# Cache dependencies first
COPY implementations/java/pom.xml ./pom.xml
# Prepare dependency cache and toolchains
RUN --mount=type=cache,target=/root/.m2 sh -lc "\
  mkdir -p /root/.m2 && \
printf '%b' '<toolchains>\n  <toolchain>\n    <type>jdk</type>\n    <provides>\n      <version>21</version>\n      <vendor>any</vendor>\n    </provides>\n    <configuration>\n      <jdkHome>/opt/java/openjdk</jdkHome>\n    </configuration>\n  </toolchain>\n</toolchains>\n' > /root/.m2/toolchains.xml && \
  mvn -B -e -ntp -DskipTests -P local-fast dependency:go-offline\
"

# Copy sources and build
COPY implementations/java/src ./src
RUN --mount=type=cache,target=/root/.m2 sh -lc "\
  mkdir -p /root/.m2 && \
printf '%b' '<toolchains>\n  <toolchain>\n    <type>jdk</type>\n    <provides>\n      <version>21</version>\n      <vendor>any</vendor>\n    </provides>\n    <configuration>\n      <jdkHome>/opt/java/openjdk</jdkHome>\n    </configuration>\n  </toolchain>\n</toolchains>\n' > /root/.m2/toolchains.xml && \
  mvn -B -e -ntp -DskipTests -P local-fast package\
"

# --- Runtime stage (distroless by default) ---
FROM gcr.io/distroless/java21-debian12:nonroot
WORKDIR /app

# OCI labels for provenance
ARG VERSION=dev
ARG BUILD_DATE
ARG VCS_REF
LABEL org.opencontainers.image.title="contact-enrichment-java" \
      org.opencontainers.image.description="Contact Enrichment Platform (Java)" \
      org.opencontainers.image.vendor="thomasvincent" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/thomasvincent/contact-enrichment-tos"

# Copy bootable jar from build stage
COPY --from=build /workspace/target/contact-enrichment-tos-*.jar /app/app.jar

# Distroless image runs as nonroot by default; declare explicitly for clarity.
USER nonroot:nonroot

# Runtime env (override with orchestrator). Health is handled by orchestrator probes.
ENV SPRING_PROFILES_ACTIVE=dev \
    SERVER_PORT=8080 \
    SELINUX_ENFORCE_CHECK=false \
    APP_SKIP_SELINUX_CHECK=true

EXPOSE 8080

ENTRYPOINT ["java","-jar","/app/app.jar"]
