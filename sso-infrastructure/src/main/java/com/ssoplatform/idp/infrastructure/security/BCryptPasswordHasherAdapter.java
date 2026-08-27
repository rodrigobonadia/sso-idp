package com.ssoplatform.idp.infrastructure.security;

import com.ssoplatform.idp.application.port.out.PasswordHasher;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.RawPassword;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Implements the {@link PasswordHasher} output port with BCrypt (strength 12 - stronger than
 * Spring Security's default of 10, a deliberate trade-off of a bit more CPU time per login for
 * better resistance against offline brute-forcing).
 */
@Component
public class BCryptPasswordHasherAdapter implements PasswordHasher {

    private static final int STRENGTH = 12;

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(STRENGTH);

    @Override
    public HashedPassword hash(RawPassword rawPassword) {
        return HashedPassword.of(encoder.encode(rawPassword.value()));
    }

    @Override
    public boolean matches(RawPassword rawPassword, HashedPassword hashedPassword) {
        return encoder.matches(rawPassword.value(), hashedPassword.value());
    }
}
