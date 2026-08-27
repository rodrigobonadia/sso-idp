package com.ssoplatform.idp.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

/**
 * Composition root of the SSO Identity Provider.
 *
 * <p>{@code sso-domain}, {@code sso-application} and {@code sso-infrastructure} are siblings of
 * this module's package, not sub-packages of it, so component scanning, entity scanning and JPA
 * repository scanning are declared explicitly here rather than relying on Spring Boot's
 * package-relative defaults.
 */
@SpringBootApplication(scanBasePackages = "com.ssoplatform.idp")
@EntityScan(basePackages = "com.ssoplatform.idp.infrastructure.persistence.entity")
@EnableJpaRepositories(basePackages = "com.ssoplatform.idp.infrastructure.persistence.repository")
public class SsoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsoApplication.class, args);
    }
}
