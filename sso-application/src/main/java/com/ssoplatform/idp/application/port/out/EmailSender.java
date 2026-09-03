package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.mfa.RawEmailOtpCode;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;

/**
 * Output port for outbound e-mail. Implemented in {@code sso-infrastructure} - a mock/log adapter
 * for now (Phase 2.2), swappable later for a real provider (SMTP, SendGrid, SES, ...) without any
 * use case changing, since this port only ever deals in domain types, never provider-specific
 * concepts (templates, API keys, ...).
 *
 * <p>Takes the raw token and tenant slug rather than a ready-made link: building the actual URL
 * needs deployment configuration (scheme, base domain, port) that the application layer must not
 * know about - that assembly happens in the adapter.
 */
public interface EmailSender {

    void sendVerificationEmail(Email recipient, String tenantSlug, RawVerificationToken token);

    void sendPasswordResetEmail(Email recipient, String tenantSlug, RawVerificationToken token);

    /**
     * Sends a Phase 4.2 e-mail OTP code - either to confirm enrollment or to satisfy a login
     * challenge (the two purposes need identical delivery, so one method serves both; see {@code
     * EnableEmailOtpUseCase}/{@code LoginUseCase}). Unlike the two methods above, there is no link
     * to assemble: the code itself IS the payload the user must read and type back in, so this
     * takes the raw code directly rather than a token to embed in a URL.
     */
    void sendMfaEmailOtpCode(Email recipient, RawEmailOtpCode code);
}
