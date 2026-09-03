package com.ssoplatform.idp.infrastructure.security;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.domain.mfa.TotpCode;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

class HmacSha1TotpCodeVerifierAdapterTest {

    // RFC 6238 Appendix B's published SHA-1 test vectors use this exact 20-byte ASCII secret and
    // publish an 8-digit code per timestamp; this system truncates to 6 digits (CODE_DIGITS), but
    // since 10^6 divides 10^8, the 6-digit code is exactly the last 6 digits of the RFC's 8-digit
    // value (a mod 10^6 == (a mod 10^8) mod 10^6) - e.g. T=59 -> RFC's "94287082" -> "287082" here.
    private static final byte[] RFC_6238_SECRET = "12345678901234567890".getBytes(StandardCharsets.UTF_8);

    private final HmacSha1TotpCodeVerifierAdapter adapter = new HmacSha1TotpCodeVerifierAdapter();

    @ParameterizedTest
    @CsvSource({
        "1, 287082", // T = 59s
        "37037036, 081804", // T = 1111111109s
        "37037037, 050471", // T = 1111111111s
        "41152263, 005924" // T = 1234567890s
    })
    void generateCodeMatchesRfc6238AppendixBTestVectorsTruncatedToSixDigits(long timeStep, String expectedCode) {
        assertThat(HmacSha1TotpCodeVerifierAdapter.generateCode(RFC_6238_SECRET, timeStep)).isEqualTo(expectedCode);
    }

    @Test
    void verifyAcceptsTheCodeForTheCurrentTimeStep() {
        byte[] secret = "any-arbitrary-secret-bytes".getBytes(StandardCharsets.UTF_8);
        long currentStep = (System.currentTimeMillis() / 1000L) / 30;
        TotpCode currentCode = TotpCode.of(HmacSha1TotpCodeVerifierAdapter.generateCode(secret, currentStep));

        assertThat(adapter.verify(secret, currentCode)).isTrue();
    }

    @Test
    void verifyAcceptsACodeFromOneStepInThePastOrFutureForClockDriftTolerance() {
        byte[] secret = "any-arbitrary-secret-bytes".getBytes(StandardCharsets.UTF_8);
        long currentStep = (System.currentTimeMillis() / 1000L) / 30;
        TotpCode previousStepCode =
                TotpCode.of(HmacSha1TotpCodeVerifierAdapter.generateCode(secret, currentStep - 1));
        TotpCode nextStepCode = TotpCode.of(HmacSha1TotpCodeVerifierAdapter.generateCode(secret, currentStep + 1));

        assertThat(adapter.verify(secret, previousStepCode)).isTrue();
        assertThat(adapter.verify(secret, nextStepCode)).isTrue();
    }

    @Test
    void verifyRejectsACodeFromTwoStepsAway() {
        byte[] secret = "any-arbitrary-secret-bytes".getBytes(StandardCharsets.UTF_8);
        long currentStep = (System.currentTimeMillis() / 1000L) / 30;
        TotpCode farCode = TotpCode.of(HmacSha1TotpCodeVerifierAdapter.generateCode(secret, currentStep + 2));

        assertThat(adapter.verify(secret, farCode)).isFalse();
    }

    @Test
    void verifyRejectsACodeGeneratedWithADifferentSecret() {
        byte[] secret = "the-real-secret".getBytes(StandardCharsets.UTF_8);
        byte[] otherSecret = "a-completely-different-secret".getBytes(StandardCharsets.UTF_8);
        long currentStep = (System.currentTimeMillis() / 1000L) / 30;
        TotpCode codeForOtherSecret =
                TotpCode.of(HmacSha1TotpCodeVerifierAdapter.generateCode(otherSecret, currentStep));

        assertThat(adapter.verify(secret, codeForOtherSecret)).isFalse();
    }
}
