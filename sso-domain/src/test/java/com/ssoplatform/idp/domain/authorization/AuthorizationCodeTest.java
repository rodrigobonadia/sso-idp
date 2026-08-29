package com.ssoplatform.idp.domain.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.domain.verification.VerificationTokenAlreadyConsumedException;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;

class AuthorizationCodeTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final OAuthClientId CLIENT_ID = OAuthClientId.generate();
    private static final UserId USER_ID = UserId.generate();
    private static final TokenHash CODE_HASH = TokenHash.of("some-hash-value");
    private static final RedirectUri REDIRECT_URI = RedirectUri.of("https://app.example.com/callback");
    private static final Set<String> SCOPES = Set.of("openid", "profile");
    private static final CodeChallenge CODE_CHALLENGE = CodeChallenge.of("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");

    private static AuthorizationCode issue() {
        return issue(null);
    }

    private static AuthorizationCode issue(String nonce) {
        return AuthorizationCode.issue(
                TENANT_ID, CLIENT_ID, USER_ID, CODE_HASH, REDIRECT_URI, SCOPES, CODE_CHALLENGE, nonce, NOW, Duration.ofMinutes(5));
    }

    @Test
    void issuingSetsExpiryToNowPlusValidityAndIsUnconsumed() {
        AuthorizationCode code = issue();

        assertThat(code.tenantId()).isEqualTo(TENANT_ID);
        assertThat(code.oauthClientId()).isEqualTo(CLIENT_ID);
        assertThat(code.userId()).isEqualTo(USER_ID);
        assertThat(code.codeHash()).isEqualTo(CODE_HASH);
        assertThat(code.redirectUri()).isEqualTo(REDIRECT_URI);
        assertThat(code.scopes()).isEqualTo(SCOPES);
        assertThat(code.codeChallenge()).isEqualTo(CODE_CHALLENGE);
        assertThat(code.nonce()).isNull();
        assertThat(code.expiresAt()).isEqualTo(NOW.plus(Duration.ofMinutes(5)));
        assertThat(code.createdAt()).isEqualTo(NOW);
        assertThat(code.isConsumed()).isFalse();
    }

    @Test
    void issuingCarriesANonceWhenSupplied() {
        AuthorizationCode code = issue("some-nonce-value");

        assertThat(code.nonce()).isEqualTo("some-nonce-value");
    }

    @Test
    void issuingRejectsEmptyScopes() {
        assertThatThrownBy(() -> AuthorizationCode.issue(
                        TENANT_ID, CLIENT_ID, USER_ID, CODE_HASH, REDIRECT_URI, Set.of(), CODE_CHALLENGE, null, NOW,
                        Duration.ofMinutes(5)))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void consumingAValidCodeMarksItConsumed() {
        AuthorizationCode code = issue();

        code.consume(NOW.plusSeconds(10));

        assertThat(code.isConsumed()).isTrue();
        assertThat(code.consumedAt()).isEqualTo(NOW.plusSeconds(10));
    }

    @Test
    void rejectsConsumingTheSameCodeTwice() {
        AuthorizationCode code = issue();
        code.consume(NOW.plusSeconds(10));

        assertThatThrownBy(() -> code.consume(NOW.plusSeconds(20)))
                .isInstanceOf(VerificationTokenAlreadyConsumedException.class);
    }

    @Test
    void rejectsConsumingAnExpiredCode() {
        AuthorizationCode code = issue();

        assertThatThrownBy(() -> code.consume(NOW.plus(Duration.ofMinutes(10))))
                .isInstanceOf(VerificationTokenExpiredException.class);
    }

    @Test
    void isExpiredReflectsWhetherNowIsPastTheExpiryInstant() {
        AuthorizationCode code = issue();

        assertThat(code.isExpired(NOW.plus(Duration.ofMinutes(4)))).isFalse();
        assertThat(code.isExpired(NOW.plus(Duration.ofMinutes(10)))).isTrue();
    }

    @Test
    void reconstituteRestoresAnExistingCode() {
        var id = AuthorizationCodeId.generate();
        Instant expiresAt = NOW.plus(Duration.ofMinutes(5));
        Instant consumedAt = NOW.plusSeconds(5);

        AuthorizationCode code = AuthorizationCode.reconstitute(
                id, TENANT_ID, CLIENT_ID, USER_ID, CODE_HASH, REDIRECT_URI, SCOPES, CODE_CHALLENGE, "reconstituted-nonce",
                expiresAt, consumedAt, NOW);

        assertThat(code.id()).isEqualTo(id);
        assertThat(code.nonce()).isEqualTo("reconstituted-nonce");
        assertThat(code.isConsumed()).isTrue();
        assertThat(code.expiresAt()).isEqualTo(expiresAt);
    }

    @Test
    void equalityIsBasedOnId() {
        AuthorizationCode code = issue();
        AuthorizationCode reloaded = AuthorizationCode.reconstitute(
                code.id(),
                code.tenantId(),
                code.oauthClientId(),
                code.userId(),
                code.codeHash(),
                code.redirectUri(),
                code.scopes(),
                code.codeChallenge(),
                code.nonce(),
                code.expiresAt(),
                null,
                code.createdAt());

        assertThat(code).isEqualTo(reloaded);
        assertThat(code).hasSameHashCodeAs(reloaded);
    }
}
