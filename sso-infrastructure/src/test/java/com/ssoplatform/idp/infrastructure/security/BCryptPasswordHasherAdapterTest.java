package com.ssoplatform.idp.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.RawPassword;
import org.junit.jupiter.api.Test;

class BCryptPasswordHasherAdapterTest {

    private final BCryptPasswordHasherAdapter hasher = new BCryptPasswordHasherAdapter();

    @Test
    void hashProducesABCryptValueDifferentFromThePlaintext() {
        RawPassword password = RawPassword.of("Str0ng!Passw0rd");

        HashedPassword hashed = hasher.hash(password);

        assertThat(hashed.value()).isNotEqualTo(password.value());
        assertThat(hashed.value()).startsWith("$2a$12$");
    }

    @Test
    void matchesReturnsTrueForTheCorrectPassword() {
        RawPassword password = RawPassword.of("Str0ng!Passw0rd");
        HashedPassword hashed = hasher.hash(password);

        assertThat(hasher.matches(password.value(), hashed)).isTrue();
    }

    @Test
    void matchesReturnsFalseForAWrongPassword() {
        RawPassword correct = RawPassword.of("Str0ng!Passw0rd");
        HashedPassword hashed = hasher.hash(correct);

        assertThat(hasher.matches("An0ther!Passw0rd", hashed)).isFalse();
    }

    @Test
    void matchesReturnsFalseForACandidateThatWouldNeverPassTheStrengthPolicyRatherThanThrowing() {
        RawPassword correct = RawPassword.of("Str0ng!Passw0rd");
        HashedPassword hashed = hasher.hash(correct);

        // A short, all-lowercase guess would fail RawPassword.of()'s strength policy - matches()
        // must still just return false for it, not throw, since a wrong-shaped guess is simply a
        // wrong password.
        assertThat(hasher.matches("wrong", hashed)).isFalse();
    }

    @Test
    void hashingTheSamePasswordTwiceProducesDifferentSaltedHashes() {
        RawPassword password = RawPassword.of("Str0ng!Passw0rd");

        HashedPassword first = hasher.hash(password);
        HashedPassword second = hasher.hash(password);

        assertThat(first.value()).isNotEqualTo(second.value());
        assertThat(hasher.matches(password.value(), first)).isTrue();
        assertThat(hasher.matches(password.value(), second)).isTrue();
    }
}
