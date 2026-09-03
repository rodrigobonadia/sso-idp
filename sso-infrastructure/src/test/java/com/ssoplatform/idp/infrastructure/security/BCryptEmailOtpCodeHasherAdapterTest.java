package com.ssoplatform.idp.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.mfa.EmailOtpCodeHash;
import com.ssoplatform.idp.domain.mfa.RawEmailOtpCode;
import org.junit.jupiter.api.Test;

class BCryptEmailOtpCodeHasherAdapterTest {

    private final BCryptEmailOtpCodeHasherAdapter hasher = new BCryptEmailOtpCodeHasherAdapter();

    @Test
    void hashProducesABCryptValueDifferentFromThePlaintext() {
        RawEmailOtpCode code = RawEmailOtpCode.generate();

        EmailOtpCodeHash hashed = hasher.hash(code);

        assertThat(hashed.value()).isNotEqualTo(code.value());
        assertThat(hashed.value()).startsWith("$2a$12$");
    }

    @Test
    void matchesReturnsTrueForTheCorrectCode() {
        RawEmailOtpCode code = RawEmailOtpCode.generate();
        EmailOtpCodeHash hashed = hasher.hash(code);

        assertThat(hasher.matches(code, hashed)).isTrue();
    }

    @Test
    void matchesReturnsFalseForAWrongCode() {
        // A 6-digit code has only ~20 bits of entropy, unlike a RawRecoveryCode's ~50 - use a
        // fixed, deliberately different candidate rather than a second random generation, so this
        // test can never flake on an astronomically unlikely (but not impossible) collision.
        RawEmailOtpCode correct = RawEmailOtpCode.of("123456");
        RawEmailOtpCode wrong = RawEmailOtpCode.of("654321");
        EmailOtpCodeHash hashed = hasher.hash(correct);

        assertThat(hasher.matches(wrong, hashed)).isFalse();
    }

    @Test
    void hashingTheSameCodeTwiceProducesDifferentSaltedHashes() {
        RawEmailOtpCode code = RawEmailOtpCode.generate();

        EmailOtpCodeHash first = hasher.hash(code);
        EmailOtpCodeHash second = hasher.hash(code);

        assertThat(first.value()).isNotEqualTo(second.value());
        assertThat(hasher.matches(code, first)).isTrue();
        assertThat(hasher.matches(code, second)).isTrue();
    }
}
