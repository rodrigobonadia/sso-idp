package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.RawPassword;

/**
 * Output port that hides the concrete password hashing algorithm (BCrypt, Argon2, ...) from the
 * application layer. Implemented in {@code sso-infrastructure}.
 *
 * <p>{@code hash} takes a {@link RawPassword} - a value that has already passed the platform's
 * strength policy - because it is only ever called when a new password is being set (registration,
 * change-password). {@code matches} deliberately takes a plain {@code String} instead: it compares
 * a login attempt's candidate against an already-stored hash, and that candidate must never be run
 * through the strength policy first. A wrong-shaped guess (too short, missing a character class)
 * is simply a wrong password and must fail the same way any other wrong password does; rejecting
 * it with a strength-policy error would leak information and would also wrongly lock out a real
 * user whose genuine password predates a later policy tightening.
 */
public interface PasswordHasher {

    HashedPassword hash(RawPassword rawPassword);

    boolean matches(String rawPassword, HashedPassword hashedPassword);
}
