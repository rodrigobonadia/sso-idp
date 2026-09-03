package com.ssoplatform.idp.infrastructure.security;

import com.ssoplatform.idp.application.port.out.EmailOtpCodeHasher;
import com.ssoplatform.idp.domain.mfa.EmailOtpCodeHash;
import com.ssoplatform.idp.domain.mfa.RawEmailOtpCode;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Implements the {@link EmailOtpCodeHasher} output port with BCrypt (same strength as {@link
 * BCryptRecoveryCodeHasherAdapter}) - see the port's Javadoc for why a 6-digit e-mail OTP code's
 * ~20 bits of entropy calls for a slow, salted algorithm rather than {@code
 * Sha256VerificationTokenHasherAdapter}'s fast unsalted approach.
 */
@Component
public class BCryptEmailOtpCodeHasherAdapter implements EmailOtpCodeHasher {

    private static final int STRENGTH = 12;

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(STRENGTH);

    @Override
    public EmailOtpCodeHash hash(RawEmailOtpCode rawCode) {
        return EmailOtpCodeHash.of(encoder.encode(rawCode.value()));
    }

    @Override
    public boolean matches(RawEmailOtpCode candidate, EmailOtpCodeHash hash) {
        return encoder.matches(candidate.value(), hash.value());
    }
}
