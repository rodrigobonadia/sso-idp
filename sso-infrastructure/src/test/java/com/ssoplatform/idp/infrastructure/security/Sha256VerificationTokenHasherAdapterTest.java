package com.ssoplatform.idp.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import org.junit.jupiter.api.Test;

class Sha256VerificationTokenHasherAdapterTest {

    private final Sha256VerificationTokenHasherAdapter hasher = new Sha256VerificationTokenHasherAdapter();

    @Test
    void hashProducesA64CharacterHexDigestDifferentFromThePlaintext() {
        RawVerificationToken token = RawVerificationToken.generate();

        TokenHash hashed = hasher.hash(token);

        assertThat(hashed.value()).isNotEqualTo(token.value());
        assertThat(hashed.value()).hasSize(64);
        assertThat(hashed.value()).matches("^[0-9a-f]{64}$");
    }

    @Test
    void hashingTheSameTokenTwiceProducesTheSameDigest() {
        RawVerificationToken token = RawVerificationToken.generate();

        TokenHash first = hasher.hash(token);
        TokenHash second = hasher.hash(token);

        assertThat(first).isEqualTo(second);
    }

    @Test
    void hashingDifferentTokensProducesDifferentDigests() {
        RawVerificationToken first = RawVerificationToken.generate();
        RawVerificationToken second = RawVerificationToken.generate();

        assertThat(hasher.hash(first)).isNotEqualTo(hasher.hash(second));
    }
}
