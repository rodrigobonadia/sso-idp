package com.ssoplatform.idp.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.mfa.RawRecoveryCode;
import com.ssoplatform.idp.domain.mfa.RecoveryCodeHash;
import org.junit.jupiter.api.Test;

class BCryptRecoveryCodeHasherAdapterTest {

    private final BCryptRecoveryCodeHasherAdapter hasher = new BCryptRecoveryCodeHasherAdapter();

    @Test
    void hashProducesABCryptValueDifferentFromThePlaintext() {
        RawRecoveryCode code = RawRecoveryCode.generate();

        RecoveryCodeHash hashed = hasher.hash(code);

        assertThat(hashed.value()).isNotEqualTo(code.value());
        assertThat(hashed.value()).startsWith("$2a$12$");
    }

    @Test
    void matchesReturnsTrueForTheCorrectCode() {
        RawRecoveryCode code = RawRecoveryCode.generate();
        RecoveryCodeHash hashed = hasher.hash(code);

        assertThat(hasher.matches(code, hashed)).isTrue();
    }

    @Test
    void matchesReturnsFalseForAWrongCode() {
        RawRecoveryCode correct = RawRecoveryCode.generate();
        RawRecoveryCode wrong = RawRecoveryCode.generate();
        RecoveryCodeHash hashed = hasher.hash(correct);

        assertThat(hasher.matches(wrong, hashed)).isFalse();
    }

    @Test
    void hashingTheSameCodeTwiceProducesDifferentSaltedHashes() {
        RawRecoveryCode code = RawRecoveryCode.generate();

        RecoveryCodeHash first = hasher.hash(code);
        RecoveryCodeHash second = hasher.hash(code);

        assertThat(first.value()).isNotEqualTo(second.value());
        assertThat(hasher.matches(code, first)).isTrue();
        assertThat(hasher.matches(code, second)).isTrue();
    }
}
