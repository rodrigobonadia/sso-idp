package com.ssoplatform.idp.domain.refreshtoken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import org.junit.jupiter.api.Test;

class RefreshTokenTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final OAuthClientId CLIENT_ID = OAuthClientId.generate();
    private static final UserId USER_ID = UserId.generate();
    private static final TokenHash TOKEN_HASH = TokenHash.of("some-hash-value");
    private static final Set<String> SCOPES = Set.of("openid", "profile", "offline_access");
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final Duration FAMILY_VALIDITY = Duration.ofDays(30);

    private static RefreshToken issueFirst() {
        return RefreshToken.issueFirst(TENANT_ID, CLIENT_ID, USER_ID, TOKEN_HASH, SCOPES, NOW, FAMILY_VALIDITY);
    }

    @Test
    void issuingFirstSetsFamilyExpiryToNowPlusValidityAndIsActive() {
        RefreshToken token = issueFirst();

        assertThat(token.tenantId()).isEqualTo(TENANT_ID);
        assertThat(token.oauthClientId()).isEqualTo(CLIENT_ID);
        assertThat(token.userId()).isEqualTo(USER_ID);
        assertThat(token.tokenHash()).isEqualTo(TOKEN_HASH);
        assertThat(token.scopes()).isEqualTo(SCOPES);
        assertThat(token.status()).isEqualTo(RefreshTokenStatus.ACTIVE);
        assertThat(token.isActive()).isTrue();
        assertThat(token.familyExpiresAt()).isEqualTo(NOW.plus(FAMILY_VALIDITY));
        assertThat(token.createdAt()).isEqualTo(NOW);
    }

    @Test
    void issuingFirstStartsABrandNewFamily() {
        RefreshToken first = issueFirst();
        RefreshToken another = issueFirst();

        assertThat(first.familyId()).isNotEqualTo(another.familyId());
    }

    @Test
    void issuingFirstRejectsEmptyScopes() {
        assertThatThrownBy(() -> RefreshToken.issueFirst(
                        TENANT_ID, CLIENT_ID, USER_ID, TOKEN_HASH, Set.of(), NOW, FAMILY_VALIDITY))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void continuingFamilyCarriesFamilyIdAndFamilyExpiryForwardUnchanged() {
        RefreshToken first = issueFirst();
        TokenHash nextHash = TokenHash.of("next-hash-value");
        Instant rotatedAt = NOW.plus(Duration.ofDays(1));

        RefreshToken next = RefreshToken.continueFamily(first, nextHash, rotatedAt);

        assertThat(next.familyId()).isEqualTo(first.familyId());
        assertThat(next.tenantId()).isEqualTo(first.tenantId());
        assertThat(next.oauthClientId()).isEqualTo(first.oauthClientId());
        assertThat(next.userId()).isEqualTo(first.userId());
        assertThat(next.scopes()).isEqualTo(first.scopes());
        assertThat(next.tokenHash()).isEqualTo(nextHash);
        assertThat(next.familyExpiresAt()).isEqualTo(first.familyExpiresAt());
        assertThat(next.createdAt()).isEqualTo(rotatedAt);
        assertThat(next.status()).isEqualTo(RefreshTokenStatus.ACTIVE);
        assertThat(next.id()).isNotEqualTo(first.id());
    }

    @Test
    void rotatingAnActiveTokenMarksItRotated() {
        RefreshToken token = issueFirst();

        token.rotate(NOW.plusSeconds(10));

        assertThat(token.status()).isEqualTo(RefreshTokenStatus.ROTATED);
        assertThat(token.isActive()).isFalse();
    }

    @Test
    void rotatingAnAlreadyRotatedTokenIsTreatedAsReuse() {
        RefreshToken token = issueFirst();
        token.rotate(NOW.plusSeconds(10));

        assertThatThrownBy(() -> token.rotate(NOW.plusSeconds(20)))
                .isInstanceOf(RefreshTokenReusedException.class);
    }

    @Test
    void rotatingARevokedTokenIsTreatedAsReuse() {
        RefreshToken token = issueFirst();
        token.revoke();

        assertThatThrownBy(() -> token.rotate(NOW.plusSeconds(10)))
                .isInstanceOf(RefreshTokenReusedException.class);
    }

    @Test
    void rotatingAnExpiredButStillActiveTokenIsRejectedAsExpiredNotReused() {
        RefreshToken token = issueFirst();

        assertThatThrownBy(() -> token.rotate(NOW.plus(FAMILY_VALIDITY).plusSeconds(1)))
                .isInstanceOf(VerificationTokenExpiredException.class);
    }

    @Test
    void revokeIsIdempotent() {
        RefreshToken token = issueFirst();
        token.revoke();
        token.revoke();

        assertThat(token.status()).isEqualTo(RefreshTokenStatus.REVOKED);
    }

    @Test
    void isExpiredReflectsWhetherNowIsPastTheFamilyExpiryInstant() {
        RefreshToken token = issueFirst();

        assertThat(token.isExpired(NOW.plus(FAMILY_VALIDITY).minusSeconds(1))).isFalse();
        assertThat(token.isExpired(NOW.plus(FAMILY_VALIDITY).plusSeconds(1))).isTrue();
    }

    @Test
    void reconstituteRestoresAnExistingToken() {
        var id = RefreshTokenId.generate();
        var familyId = RefreshTokenFamilyId.generate();
        Instant familyExpiresAt = NOW.plus(FAMILY_VALIDITY);

        RefreshToken token = RefreshToken.reconstitute(
                id, familyId, TENANT_ID, CLIENT_ID, USER_ID, TOKEN_HASH, SCOPES, RefreshTokenStatus.ROTATED,
                familyExpiresAt, NOW);

        assertThat(token.id()).isEqualTo(id);
        assertThat(token.familyId()).isEqualTo(familyId);
        assertThat(token.status()).isEqualTo(RefreshTokenStatus.ROTATED);
        assertThat(token.familyExpiresAt()).isEqualTo(familyExpiresAt);
    }

    @Test
    void equalityIsBasedOnId() {
        RefreshToken token = issueFirst();
        RefreshToken reloaded = RefreshToken.reconstitute(
                token.id(),
                token.familyId(),
                token.tenantId(),
                token.oauthClientId(),
                token.userId(),
                token.tokenHash(),
                token.scopes(),
                token.status(),
                token.familyExpiresAt(),
                token.createdAt());

        assertThat(token).isEqualTo(reloaded);
        assertThat(token).hasSameHashCodeAs(reloaded);
    }
}
