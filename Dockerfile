# --- Build stage -------------------------------------------------------------------------
FROM maven:3.9-eclipse-temurin-21 AS build

WORKDIR /workspace

# Copy POMs first so Maven can cache dependency resolution across source-only changes.
COPY pom.xml .
COPY sso-domain/pom.xml sso-domain/pom.xml
COPY sso-application/pom.xml sso-application/pom.xml
COPY sso-infrastructure/pom.xml sso-infrastructure/pom.xml
COPY sso-api/pom.xml sso-api/pom.xml
RUN mvn -q -B dependency:go-offline

COPY sso-domain/src sso-domain/src
COPY sso-application/src sso-application/src
COPY sso-infrastructure/src sso-infrastructure/src
COPY sso-api/src sso-api/src

RUN mvn -q -B -DskipTests package

# --- Runtime stage -------------------------------------------------------------------------
FROM eclipse-temurin:21-jre-jammy

RUN useradd --system --create-home --shell /usr/sbin/nologin sso
USER sso
WORKDIR /app

COPY --from=build /workspace/sso-api/target/sso-api.jar app.jar

EXPOSE 8080

ENTRYPOINT ["java", "-jar", "/app/app.jar"]
