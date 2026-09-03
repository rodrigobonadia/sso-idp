package com.ssoplatform.idp.application.usecase.mfa;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class Base32Test {

    // RFC 4648 §10's own test vectors, with the '=' padding stripped - this encoder is
    // deliberately unpadded (see Base32's Javadoc: EnrollTotpUseCase.SECRET_BYTE_LENGTH is always
    // a multiple of 5 bits, so real usage never produces trailing padding anyway).
    @ParameterizedTest
    @CsvSource({
        "f, MY",
        "fo, MZXQ",
        "foo, MZXW6",
        "foob, MZXW6YQ",
        "fooba, MZXW6YTB",
        "foobar, MZXW6YTBOI"
    })
    void encodeMatchesRfc4648TestVectors(String input, String expected) {
        assertThat(Base32.encode(input.getBytes(StandardCharsets.UTF_8))).isEqualTo(expected);
    }

    @Test
    void encodeOfEmptyBytesProducesAnEmptyString() {
        assertThat(Base32.encode(new byte[0])).isEmpty();
    }
}
