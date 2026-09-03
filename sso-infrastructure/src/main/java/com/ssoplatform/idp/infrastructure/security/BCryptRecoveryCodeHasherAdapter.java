package com.ssoplatform.idp.infrastructure.security;

import com.ssoplatform.idp.application.port.out.RecoveryCodeHasher;
import com.ssoplatform.idp.domain.mfa.RawRecoveryCode;
import com.ssoplatform.idp.domain.mfa.RecoveryCodeHash;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Implements the {@link RecoveryCodeHasher} output port with BCrypt (same strength as {@link
 * BCryptPasswordHasherAdapter}) - see the port's Javadoc for why a recovery code's ~50 bits of
 * entropy calls for a slow, salted algorithm rather than {@link Sha256VerificationTokenHasherAdapter}'s
 * fast unsalted approach.
 */
@Component
public class BCryptRecoveryCodeHasherAdapter implements RecoveryCodeHasher {

    private static final int STRENGTH = 12;

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(STRENGTH);

    @Override
    public RecoveryCodeHash hash(RawRecoveryCode rawCode) {
        return RecoveryCodeHash.of(encoder.encode(rawCode.value()));
    }

    @Override
    public boolean matches(RawRecoveryCode candidate, RecoveryCodeHash hash) {
        return encoder.matches(candidate.value(), hash.value());
    }
}
