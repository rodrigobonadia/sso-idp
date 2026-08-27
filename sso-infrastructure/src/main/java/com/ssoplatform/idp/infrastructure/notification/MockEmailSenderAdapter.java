package com.ssoplatform.idp.infrastructure.notification;

import com.ssoplatform.idp.application.port.out.EmailSender;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Implements the {@link EmailSender} output port by logging the verification link instead of
 * actually sending an e-mail. Phase 2.2 has no real provider integration yet (SMTP, SendGrid,
 * SES, ...) - this adapter exists so the registration flow is fully testable end-to-end without
 * one, and is swappable later for a real adapter without any use case changing, since both
 * implement the same {@link EmailSender} port.
 *
 * <p>The link scheme/port defaulted here ({@code http} on {@code server.port}) match local
 * development; a real deployment behind TLS would override {@code app.mail.link-scheme} to
 * {@code https} and typically wouldn't need a port at all (a concern that belongs to whatever
 * real adapter replaces this one, not to this mock).
 */
@Component
public class MockEmailSenderAdapter implements EmailSender {

    private static final Logger log = LoggerFactory.getLogger(MockEmailSenderAdapter.class);

    private final String tenantBaseDomain;
    private final String linkScheme;
    private final String serverPort;

    public MockEmailSenderAdapter(
            @Value("${app.tenant.base-domain}") String tenantBaseDomain,
            @Value("${app.mail.link-scheme:http}") String linkScheme,
            @Value("${server.port}") String serverPort) {
        this.tenantBaseDomain = tenantBaseDomain;
        this.linkScheme = linkScheme;
        this.serverPort = serverPort;
    }

    @Override
    public void sendVerificationEmail(Email recipient, String tenantSlug, RawVerificationToken token) {
        String verificationUrl = "%s://%s.%s:%s/verify-email?token=%s"
                .formatted(linkScheme, tenantSlug, tenantBaseDomain, serverPort, token.value());
        log.info("[MOCK EMAIL] Verification link for {}: {}", recipient.value(), verificationUrl);
    }
}
