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

        assertThat(hasher.matches(password, hashed)).isTrue();
    }

    @Test
    void matchesReturnsFalseForAWrongPassword() {
        RawPassword correct = RawPassword.of("Str0ng!Passw0rd");
        RawPassword wrong = RawPassword.of("An0ther!Passw0rd");
        HashedPassword hashed = hasher.hash(correct);

        assertThat(hasher.matches(wrong, hashed)).isFalse();
    }

    @Test
    void hashingTheSamePasswordTwiceProducesDifferentSaltedHashes() {
        RawPassword password = RawPassword.of("Str0ng!Passw0rd");

        HashedPassword first = hasher.hash(password);
        HashedPassword second = hasher.hash(password);

        assertThat(first.value()).isNotEqualTo(second.value());
        assertThat(hasher.matches(password, first)).isTrue();
        assertThat(hasher.matches(password, second)).isTrue();
    }
}
