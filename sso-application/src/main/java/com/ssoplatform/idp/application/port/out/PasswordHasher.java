package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.RawPassword;

/**
 * Output port that hides the concrete password hashing algorithm (BCrypt, Argon2, ...) from the
 * application layer. Implemented in {@code sso-infrastructure}.
 */
public interface PasswordHasher {

    HashedPassword hash(RawPassword rawPassword);

    boolean matches(RawPassword rawPassword, HashedPassword hashedPassword);
}
