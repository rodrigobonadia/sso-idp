package com.ssoplatform.idp.infrastructure.notification;

import static org.assertj.core.api.Assertions.assertThat;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

class MockEmailSenderAdapterTest {

    private final MockEmailSenderAdapter adapter =
            new MockEmailSenderAdapter("ssoplatform.example", "https", "443");
    private ListAppender<ILoggingEvent> appender;
    private Logger logger;

    @BeforeEach
    void setUp() {
        logger = (Logger) LoggerFactory.getLogger(MockEmailSenderAdapter.class);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void tearDown() {
        logger.detachAppender(appender);
    }

    @Test
    void logsAVerificationLinkBuiltFromTheTenantSubdomainAndTheRawToken() {
        RawVerificationToken token = RawVerificationToken.generate();

        adapter.sendVerificationEmail(Email.of("someone@example.com"), "acme", token);

        assertThat(appender.list).hasSize(1);
        String logged = appender.list.get(0).getFormattedMessage();
        assertThat(logged).contains("someone@example.com");
        assertThat(logged).contains("https://acme.ssoplatform.example:443/verify-email?token=" + token.value());
    }

    @Test
    void logsAPasswordResetLinkBuiltFromTheTenantSubdomainAndTheRawToken() {
        RawVerificationToken token = RawVerificationToken.generate();

        adapter.sendPasswordResetEmail(Email.of("someone@example.com"), "acme", token);

        assertThat(appender.list).hasSize(1);
        String logged = appender.list.get(0).getFormattedMessage();
        assertThat(logged).contains("someone@example.com");
        assertThat(logged).contains("https://acme.ssoplatform.example:443/reset-password?token=" + token.value());
    }
}
