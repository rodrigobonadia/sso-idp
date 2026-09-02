package com.ssoplatform.idp.domain.devicecode;

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

class DeviceCodeTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final OAuthClientId CLIENT_ID = OAuthClientId.generate();
    private static final UserId USER_ID = UserId.generate();
    private static final TokenHash DEVICE_CODE_HASH = TokenHash.of("some-hash-value");
    private static final UserCode USER_CODE = UserCode.of("WDJP-MX9K");
    private static final Set<String> SCOPES = Set.of("openid", "profile");
    private static final Instant NOW = Instant.parse("2026-01-01T00:00:00Z");
    private static final Duration VALIDITY = Duration.ofMinutes(10);

    private static DeviceCode request() {
        return DeviceCode.request(TENANT_ID, CLIENT_ID, DEVICE_CODE_HASH, USER_CODE, SCOPES, NOW, VALIDITY);
    }

    @Test
    void requestingCreatesAPendingCodeWithNoUserYet() {
        DeviceCode code = request();

        assertThat(code.tenantId()).isEqualTo(TENANT_ID);
        assertThat(code.oauthClientId()).isEqualTo(CLIENT_ID);
        assertThat(code.deviceCodeHash()).isEqualTo(DEVICE_CODE_HASH);
        assertThat(code.userCode()).isEqualTo(USER_CODE);
        assertThat(code.scopes()).isEqualTo(SCOPES);
        assertThat(code.status()).isEqualTo(DeviceCodeStatus.PENDING);
        assertThat(code.userId()).isNull();
        assertThat(code.expiresAt()).isEqualTo(NOW.plus(VALIDITY));
        assertThat(code.lastPolledAt()).isNull();
        assertThat(code.redeemedAt()).isNull();
        assertThat(code.createdAt()).isEqualTo(NOW);
    }

    @Test
    void requestingRejectsEmptyScopes() {
        assertThatThrownBy(() -> DeviceCode.request(TENANT_ID, CLIENT_ID, DEVICE_CODE_HASH, USER_CODE, Set.of(), NOW, VALIDITY))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void approvingAPendingCodeSetsTheUserAndMovesToApproved() {
        DeviceCode code = request();

        code.approve(USER_ID, NOW.plusSeconds(30));

        assertThat(code.status()).isEqualTo(DeviceCodeStatus.APPROVED);
        assertThat(code.userId()).isEqualTo(USER_ID);
    }

    @Test
    void rejectsApprovingACodeThatIsAlreadyDecided() {
        DeviceCode code = request();
        code.approve(USER_ID, NOW.plusSeconds(30));

        assertThatThrownBy(() -> code.approve(USER_ID, NOW.plusSeconds(40)))
                .isInstanceOf(DeviceCodeStateException.class);
    }

    @Test
    void rejectsApprovingAnExpiredCode() {
        DeviceCode code = request();

        assertThatThrownBy(() -> code.approve(USER_ID, NOW.plus(VALIDITY).plusSeconds(1)))
                .isInstanceOf(VerificationTokenExpiredException.class);
    }

    @Test
    void denyingAPendingCodeMovesToDenied() {
        DeviceCode code = request();

        code.deny(NOW.plusSeconds(30));

        assertThat(code.status()).isEqualTo(DeviceCodeStatus.DENIED);
        assertThat(code.userId()).isNull();
    }

    @Test
    void rejectsDenyingACodeThatIsAlreadyDecided() {
        DeviceCode code = request();
        code.deny(NOW.plusSeconds(30));

        assertThatThrownBy(() -> code.deny(NOW.plusSeconds(40)))
                .isInstanceOf(DeviceCodeStateException.class);
    }

    @Test
    void redeemingAnApprovedCodeMovesToRedeemedAndRecordsTheInstant() {
        DeviceCode code = request();
        code.approve(USER_ID, NOW.plusSeconds(30));

        code.redeem(NOW.plusSeconds(35));

        assertThat(code.status()).isEqualTo(DeviceCodeStatus.REDEEMED);
        assertThat(code.redeemedAt()).isEqualTo(NOW.plusSeconds(35));
    }

    @Test
    void rejectsRedeemingACodeThatIsNotApproved() {
        DeviceCode pending = request();
        assertThatThrownBy(() -> pending.redeem(NOW.plusSeconds(5)))
                .isInstanceOf(DeviceCodeStateException.class);

        DeviceCode denied = request();
        denied.deny(NOW.plusSeconds(5));
        assertThatThrownBy(() -> denied.redeem(NOW.plusSeconds(10)))
                .isInstanceOf(DeviceCodeStateException.class);

        DeviceCode redeemedTwice = request();
        redeemedTwice.approve(USER_ID, NOW.plusSeconds(5));
        redeemedTwice.redeem(NOW.plusSeconds(10));
        assertThatThrownBy(() -> redeemedTwice.redeem(NOW.plusSeconds(15)))
                .isInstanceOf(DeviceCodeStateException.class);
    }

    @Test
    void rejectsRedeemingAnExpiredApprovedCode() {
        DeviceCode code = request();
        code.approve(USER_ID, NOW.plusSeconds(30));

        assertThatThrownBy(() -> code.redeem(NOW.plus(VALIDITY).plusSeconds(1)))
                .isInstanceOf(VerificationTokenExpiredException.class);
    }

    @Test
    void isExpiredReflectsWhetherNowIsPastTheExpiryInstant() {
        DeviceCode code = request();

        assertThat(code.isExpired(NOW.plus(Duration.ofMinutes(9)))).isFalse();
        assertThat(code.isExpired(NOW.plus(Duration.ofMinutes(11)))).isTrue();
    }

    @Test
    void isPolledTooSoonIsFalseBeforeAnyPollHasBeenRecorded() {
        DeviceCode code = request();

        assertThat(code.isPolledTooSoon(NOW.plusSeconds(1), Duration.ofSeconds(5))).isFalse();
    }

    @Test
    void isPolledTooSoonComparesAgainstThePreviousPollNotTheCurrentOne() {
        DeviceCode code = request();
        code.recordPoll(NOW);

        assertThat(code.isPolledTooSoon(NOW.plusSeconds(2), Duration.ofSeconds(5))).isTrue();
        assertThat(code.isPolledTooSoon(NOW.plusSeconds(5), Duration.ofSeconds(5))).isFalse();

        code.recordPoll(NOW.plusSeconds(2));
        assertThat(code.lastPolledAt()).isEqualTo(NOW.plusSeconds(2));
    }

    @Test
    void reconstituteRestoresAnExistingCode() {
        var id = DeviceCodeId.generate();
        Instant expiresAt = NOW.plus(VALIDITY);
        Instant lastPolledAt = NOW.plusSeconds(5);
        Instant redeemedAt = NOW.plusSeconds(10);

        DeviceCode code = DeviceCode.reconstitute(
                id, TENANT_ID, CLIENT_ID, DEVICE_CODE_HASH, USER_CODE, SCOPES, DeviceCodeStatus.REDEEMED, USER_ID,
                expiresAt, lastPolledAt, redeemedAt, NOW);

        assertThat(code.id()).isEqualTo(id);
        assertThat(code.status()).isEqualTo(DeviceCodeStatus.REDEEMED);
        assertThat(code.userId()).isEqualTo(USER_ID);
        assertThat(code.lastPolledAt()).isEqualTo(lastPolledAt);
        assertThat(code.redeemedAt()).isEqualTo(redeemedAt);
        assertThat(code.expiresAt()).isEqualTo(expiresAt);
    }

    @Test
    void equalsAndHashCodeAreIdentityBased() {
        var id = DeviceCodeId.generate();
        Instant expiresAt = NOW.plus(VALIDITY);
        DeviceCode first = DeviceCode.reconstitute(
                id, TENANT_ID, CLIENT_ID, DEVICE_CODE_HASH, USER_CODE, SCOPES, DeviceCodeStatus.PENDING, null,
                expiresAt, null, null, NOW);
        DeviceCode sameId = DeviceCode.reconstitute(
                id, TENANT_ID, CLIENT_ID, DEVICE_CODE_HASH, USER_CODE, SCOPES, DeviceCodeStatus.DENIED, null,
                expiresAt, null, null, NOW);
        DeviceCode differentId = request();

        assertThat(first).isEqualTo(sameId);
        assertThat(first.hashCode()).isEqualTo(sameId.hashCode());
        assertThat(first).isNotEqualTo(differentId);
    }
}
