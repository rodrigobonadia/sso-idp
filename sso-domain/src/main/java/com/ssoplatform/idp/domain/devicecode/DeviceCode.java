package com.ssoplatform.idp.domain.devicecode;

import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/**
 * A device authorization request (RFC 8628), created by {@code POST /device_authorization} and
 * driven to completion by two independent actors polling/acting on it concurrently: the device
 * itself, which repeatedly presents the raw {@code device_code} to {@code POST /token} until it
 * gets an answer, and a user on a separate, browser-capable device, who visits {@code
 * verification_uri}, enters {@link #userCode}, and clicks Allow or Deny.
 *
 * <p>Reuses {@link TokenHash} for {@link #deviceCodeHash} exactly like {@code AuthorizationCode}
 * and {@code PasswordResetToken} do - the raw {@code device_code} handed to the polling device is
 * generated and validated with {@code
 * com.ssoplatform.idp.domain.verification.RawVerificationToken}, the same purpose-agnostic
 * high-entropy token type. {@link #userCode}, by contrast, is deliberately low-entropy and
 * human-typeable (see {@link UserCode}'s Javadoc) - it identifies the pending request to a human,
 * while {@code device_code} authenticates the polling device, so the two need very different
 * shapes despite guarding the same aggregate.
 *
 * <p>The status machine (see {@link DeviceCodeStatus}) is: {@code PENDING} from {@link
 * #request}, then exactly one of {@link #approve} or {@link #deny} moves it to {@code APPROVED}
 * or {@code DENIED} - both throw {@link DeviceCodeStateException} if the code is not still {@code
 * PENDING} (already decided) and {@link com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException}
 * if it is expired. From {@code APPROVED}, {@link #redeem} moves it to the terminal {@code
 * REDEEMED} state exactly once, mirroring {@code AuthorizationCode#consume}'s single-use
 * enforcement. Unlike {@code AuthorizationCode}, {@code TokenUseCase} reads {@link #status()}
 * directly rather than catching a single collapsed exception, because a {@code PENDING} vs. a
 * {@code DENIED} vs. an already-{@code REDEEMED} code must produce three different RFC 8628 {@code
 * /token} error codes ({@code authorization_pending}, {@code access_denied}, {@code invalid_grant}
 * respectively) rather than one.
 *
 * <p>{@link #recordPoll}/{@link #isPolledTooSoon} implement RFC 8628 §3.5's polling rate limit
 * ({@code slow_down}): every poll of {@code /token} calls {@link #recordPoll}, and {@code
 * TokenUseCase} checks {@link #isPolledTooSoon} against the platform's fixed polling interval
 * beforehand to decide whether to reject the poll as too fast.
 */
public final class DeviceCode {

    private final DeviceCodeId id;
    private final TenantId tenantId;
    private final OAuthClientId oauthClientId;
    private final TokenHash deviceCodeHash;
    private final UserCode userCode;
    private final Set<String> scopes;
    private DeviceCodeStatus status;
    private UserId userId;
    private final Instant expiresAt;
    private Instant lastPolledAt;
    private Instant redeemedAt;
    private final Instant createdAt;

    private DeviceCode(
            DeviceCodeId id,
            TenantId tenantId,
            OAuthClientId oauthClientId,
            TokenHash deviceCodeHash,
            UserCode userCode,
            Set<String> scopes,
            DeviceCodeStatus status,
            UserId userId,
            Instant expiresAt,
            Instant lastPolledAt,
            Instant redeemedAt,
            Instant createdAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.oauthClientId = oauthClientId;
        this.deviceCodeHash = deviceCodeHash;
        this.userCode = userCode;
        this.scopes = scopes;
        this.status = status;
        this.userId = userId;
        this.expiresAt = expiresAt;
        this.lastPolledAt = lastPolledAt;
        this.redeemedAt = redeemedAt;
        this.createdAt = createdAt;
    }

    /** Creates a brand-new, {@code PENDING} device code, valid from {@code now} for {@code validity}. */
    public static DeviceCode request(
            TenantId tenantId,
            OAuthClientId oauthClientId,
            TokenHash deviceCodeHash,
            UserCode userCode,
            Set<String> scopes,
            Instant now,
            Duration validity) {
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(oauthClientId, "oauthClientId must not be null");
        Objects.requireNonNull(deviceCodeHash, "deviceCodeHash must not be null");
        Objects.requireNonNull(userCode, "userCode must not be null");
        Objects.requireNonNull(scopes, "scopes must not be null");
        if (scopes.isEmpty()) {
            throw new IllegalArgumentException("A device code must carry at least one scope");
        }
        Objects.requireNonNull(now, "now must not be null");
        Objects.requireNonNull(validity, "validity must not be null");
        return new DeviceCode(
                DeviceCodeId.generate(),
                tenantId,
                oauthClientId,
                deviceCodeHash,
                userCode,
                Set.copyOf(scopes),
                DeviceCodeStatus.PENDING,
                null,
                now.plus(validity),
                null,
                null,
                now);
    }

    /** Reconstitutes a device code that already exists (used by persistence adapters). */
    public static DeviceCode reconstitute(
            DeviceCodeId id,
            TenantId tenantId,
            OAuthClientId oauthClientId,
            TokenHash deviceCodeHash,
            UserCode userCode,
            Set<String> scopes,
            DeviceCodeStatus status,
            UserId userId,
            Instant expiresAt,
            Instant lastPolledAt,
            Instant redeemedAt,
            Instant createdAt) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(oauthClientId, "oauthClientId must not be null");
        Objects.requireNonNull(deviceCodeHash, "deviceCodeHash must not be null");
        Objects.requireNonNull(userCode, "userCode must not be null");
        Objects.requireNonNull(scopes, "scopes must not be null");
        Objects.requireNonNull(status, "status must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        return new DeviceCode(
                id,
                tenantId,
                oauthClientId,
                deviceCodeHash,
                userCode,
                Set.copyOf(scopes),
                status,
                userId,
                expiresAt,
                lastPolledAt,
                redeemedAt,
                createdAt);
    }

    /**
     * Records that {@code userId} has approved this device on the verification page. Requires the
     * code to still be {@code PENDING} and unexpired.
     */
    public void approve(UserId userId, Instant now) {
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(now, "now must not be null");
        requirePendingAndUnexpired(now);
        this.userId = userId;
        this.status = DeviceCodeStatus.APPROVED;
    }

    /** Records that the user denied this device on the verification page. Requires {@code PENDING} and unexpired. */
    public void deny(Instant now) {
        Objects.requireNonNull(now, "now must not be null");
        requirePendingAndUnexpired(now);
        this.status = DeviceCodeStatus.DENIED;
    }

    private void requirePendingAndUnexpired(Instant now) {
        if (status != DeviceCodeStatus.PENDING) {
            throw new DeviceCodeStateException("Device code is no longer pending (current status: " + status + ")");
        }
        if (isExpired(now)) {
            throw new VerificationTokenExpiredException();
        }
    }

    /**
     * Marks the code as redeemed, called by {@code TokenUseCase} exactly once, after a successful
     * poll of {@code /token} for an {@code APPROVED} code. Requires {@code APPROVED} and
     * unexpired - {@code TokenUseCase} is expected to have already read {@link #status()} to
     * select the right RFC 8628 error code for every other status, so reaching this method with
     * the wrong status indicates a caller bug rather than a normal flow outcome.
     */
    public void redeem(Instant now) {
        Objects.requireNonNull(now, "now must not be null");
        if (status != DeviceCodeStatus.APPROVED) {
            throw new DeviceCodeStateException("Device code is not approved (current status: " + status + ")");
        }
        if (isExpired(now)) {
            throw new VerificationTokenExpiredException();
        }
        this.status = DeviceCodeStatus.REDEEMED;
        this.redeemedAt = now;
    }

    public boolean isExpired(Instant now) {
        return now.isAfter(expiresAt);
    }

    /** Records that the device polled {@code /token} at {@code now}, for the next {@link #isPolledTooSoon} check. */
    public void recordPoll(Instant now) {
        this.lastPolledAt = Objects.requireNonNull(now, "now must not be null");
    }

    /**
     * {@code true} when the device is polling faster than {@code interval} allows (RFC 8628
     * §3.5's {@code slow_down}), judged against the poll before this one - call this BEFORE {@link
     * #recordPoll} for the current poll, or it will always compare a poll against itself.
     */
    public boolean isPolledTooSoon(Instant now, Duration interval) {
        Objects.requireNonNull(now, "now must not be null");
        Objects.requireNonNull(interval, "interval must not be null");
        return lastPolledAt != null && now.isBefore(lastPolledAt.plus(interval));
    }

    public DeviceCodeId id() {
        return id;
    }

    public TenantId tenantId() {
        return tenantId;
    }

    public OAuthClientId oauthClientId() {
        return oauthClientId;
    }

    public TokenHash deviceCodeHash() {
        return deviceCodeHash;
    }

    public UserCode userCode() {
        return userCode;
    }

    public Set<String> scopes() {
        return Set.copyOf(scopes);
    }

    public DeviceCodeStatus status() {
        return status;
    }

    /** The user who approved this device, or {@code null} until {@link #approve} is called. */
    public UserId userId() {
        return userId;
    }

    public Instant expiresAt() {
        return expiresAt;
    }

    /** The instant of the most recent {@link #recordPoll}, or {@code null} if never polled. */
    public Instant lastPolledAt() {
        return lastPolledAt;
    }

    /** The instant {@link #redeem} succeeded, or {@code null} if not yet redeemed. */
    public Instant redeemedAt() {
        return redeemedAt;
    }

    public Instant createdAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DeviceCode that)) return false;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
