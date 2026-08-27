package com.ssoplatform.idp.infrastructure;

import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

/**
 * Minimal Spring Boot context for {@code @DataJpaTest} slices in this module: sso-infrastructure
 * is a library, not a bootable application, so there is no {@code @SpringBootApplication} class
 * for the test framework to find on its own.
 */
@SpringBootConfiguration
@EnableAutoConfiguration
@EntityScan(basePackages = "com.ssoplatform.idp.infrastructure.persistence.entity")
@EnableJpaRepositories(basePackages = "com.ssoplatform.idp.infrastructure.persistence.repository")
public class InfrastructureTestConfiguration {}
