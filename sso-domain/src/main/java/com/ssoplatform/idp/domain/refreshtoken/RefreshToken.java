package com.ssoplatform.idp.domain.refreshtoken;

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
 * An opaque, rotating refresh token issued by {@code POST /token} (Phase 3.6) when a client
 * redeems an {@code authorization_code} grant carrying the {@code offline_access} scope, and later
 * redeemed - and rotated - via {@code grant_type=refresh_token}.
 *
 * <p>Reuses {@link TokenHash} from {@code domain.verification} for the same reason {@link
 * com.ssoplatform.idp.domain.authorization.AuthorizationCode} does: the raw token value is a
 * purpose-agnostic high-entropy random string, generated and validated with {@code
 * RawVerificationToken}, and only its hash is ever persisted.
 *
 * <p>Unlike an authorization code, a refresh token is not simply "consumed" once - it is
 * <b>rotated</b>: every successful redemption via {@code grant_type=refresh_token} issues a
 * brand-new {@code RefreshToken} row ({@link #continueFamily}) sharing the same {@link
 * #familyId}, and marks the presented row {@link RefreshTokenStatus#ROTATED} ({@link
 * #rotate(Instant)}) so its raw value can never be redeemed again. All rows sharing a {@link
 * #familyId} descend from one original login and form a single chain; presenting a row that is
 * already {@code ROTATED} (or {@code REVOKED}) is therefore a reuse/theft signal, not an ordinary
 * client error, and must revoke the <b>entire family</b> - every row that shares {@link
 * #familyId} - forcing the user to re-authenticate from scratch (see {@code
 * TokenUseCase.executeRefreshTokenGrant}).
 *
 * <p>{@link #familyExpiresAt} is a single absolute instant computed once, when the family is
 * created ({@link #issueFirst}), and copied unchanged onto every rotated descendant ({@link
 * #continueFamily}) - a fixed 30-day validity window for the whole chain, never extended or
 * "renewed" by rotation. Once that instant passes, the family is dead regardless of how recently
 * it was last rotated, and the user must re-authenticate.
 */
public final class RefreshToken {

    private final RefreshTokenId id;
    private final RefreshTokenFamilyId familyId;
    private final TenantId tenantId;
    private final OAuthClientId oauthClientId;
    private final UserId userId;
    private final TokenHash tokenHash;
    private final Set<String> scopes;
    private RefreshTokenStatus status;
    private final Instant familyExpiresAt;
    private final Instant createdAt;

    private RefreshToken(
            RefreshTokenId id,
            RefreshTokenFamilyId familyId,
            TenantId tenantId,
            OAuthClientId oauthClientId,
            UserId userId,
            TokenHash tokenHash,
            Set<String> scopes,
            RefreshTokenStatus status,
            Instant familyExpiresAt,
            Instant createdAt) {
        this.id = id;
        this.familyId = familyId;
        this.tenantId = tenantId;
        this.oauthClientId = oauthClientId;
        this.userId = userId;
        this.tokenHash = tokenHash;
        this.scopes = scopes;
        this.status = status;
        this.familyExpiresAt = familyExpiresAt;
        this.createdAt = createdAt;
    }

    /**
     * Issues the FIRST refresh token of a brand-new family, e.g. when an {@code
     * authorization_code} grant is redeemed with {@code offline_access} in its scopes. Starts a
     * new {@link RefreshTokenFamilyId} and computes {@link #familyExpiresAt} as {@code
     * now.plus(familyValidity)} - the fixed absolute expiry every later rotation in this family
     * will inherit unchanged.
     */
    public static RefreshToken issueFirst(
            TenantId tenantId,
            OAuthClientId oauthClientId,
            UserId userId,
            TokenHash tokenHash,
            Set<String> scopes,
            Instant now,
            Duration familyValidity) {
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(oauthClientId, "oauthClientId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(tokenHash, "tokenHash must not be null");
        Objects.requireNonNull(scopes, "scopes must not be null");
        if (scopes.isEmpty()) {
            throw new IllegalArgumentException("A refresh token must carry at least one scope");
        }
        Objects.requireNonNull(now, "now must not be null");
        Objects.requireNonNull(familyValidity, "familyValidity must not be null");
        return new RefreshToken(
                RefreshTokenId.generate(),
                RefreshTokenFamilyId.generate(),
                tenantId,
                oauthClientId,
                userId,
                tokenHash,
                Set.copyOf(scopes),
                RefreshTokenStatus.ACTIVE,
                now.plus(familyValidity),
                now);
    }

    /**
     * Issues the NEXT refresh token in an existing family, as part of rotating {@code previous}
     * (see {@link #rotate(Instant)}). Carries {@link #familyId}, tenant/client/user, and scopes
     * forward unchanged from {@code previous}, and - critically - copies {@link
     * #familyExpiresAt} unchanged too: rotation never extends the family's fixed 30-day validity
     * window.
     */
    public static RefreshToken continueFamily(RefreshToken previous, TokenHash newTokenHash, Instant now) {
        Objects.requireNonNull(previous, "previous must not be null");
        Objects.requireNonNull(newTokenHash, "newTokenHash must not be null");
        Objects.requireNonNull(now, "now must not be null");
        return new RefreshToken(
                RefreshTokenId.generate(),
                previous.familyId,
                previous.tenantId,
                previous.oauthClientId,
                previous.userId,
                newTokenHash,
                previous.scopes,
                RefreshTokenStatus.ACTIVE,
                previous.familyExpiresAt,
                now);
    }

    /** Reconstitutes a refresh token row that already exists (used by persistence adapters). */
    public static RefreshToken reconstitute(
            RefreshTokenId id,
            RefreshTokenFamilyId familyId,
            TenantId tenantId,
            OAuthClientId oauthClientId,
            UserId userId,
            TokenHash tokenHash,
            Set<String> scopes,
            RefreshTokenStatus status,
            Instant familyExpiresAt,
            Instant createdAt) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(familyId, "familyId must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(oauthClientId, "oauthClientId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(tokenHash, "tokenHash must not be null");
        Objects.requireNonNull(scopes, "scopes must not be null");
        Objects.requireNonNull(status, "status must not be null");
        Objects.requireNonNull(familyExpiresAt, "familyExpiresAt must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        return new RefreshToken(
                id,
                familyId,
                tenantId,
                oauthClientId,
                userId,
                tokenHash,
                Set.copyOf(scopes),
                status,
                familyExpiresAt,
                createdAt);
    }

    /**
     * Marks this token as redeemed via {@code grant_type=refresh_token}, transitioning {@link
     * RefreshTokenStatus#ACTIVE} to {@link RefreshTokenStatus#ROTATED}. The caller ({@code
     * TokenUseCase}) is responsible for issuing and persisting the next token in the family (see
     * {@link #continueFamily}) immediately afterwards.
     *
     * @throws RefreshTokenReusedException if this token is not currently {@code ACTIVE} - i.e. it
     *     was already rotated or already revoked. Per this project's reuse-detection policy, the
     *     caller must respond by revoking every token in {@link #familyId}, not just this one.
     * @throws VerificationTokenExpiredException if this token is still {@code ACTIVE} but {@link
     *     #familyExpiresAt} has passed - the family has simply expired; no theft is implied.
     */
    public void rotate(Instant now) {
        Objects.requireNonNull(now, "now must not be null");
        if (status != RefreshTokenStatus.ACTIVE) {
            throw new RefreshTokenReusedException();
        }
        if (isExpired(now)) {
            throw new VerificationTokenExpiredException();
        }
        this.status = RefreshTokenStatus.ROTATED;
    }

    /**
     * Unconditionally marks this token {@link RefreshTokenStatus#REVOKED}. Idempotent - safe to
     * call on a token that is already {@code ROTATED} or already {@code REVOKED} - so a
     * full-family revocation sweep can call this on every row of a family without inspecting each
     * row's current status first.
     */
    public void revoke() {
        this.status = RefreshTokenStatus.REVOKED;
    }

    public boolean isExpired(Instant now) {
        return now.isAfter(familyExpiresAt);
    }

    public boolean isActive() {
        return status == RefreshTokenStatus.ACTIVE;
    }

    public RefreshTokenId id() {
        return id;
    }

    public RefreshTokenFamilyId familyId() {
        return familyId;
    }

    public TenantId tenantId() {
        return tenantId;
    }

    public OAuthClientId oauthClientId() {
        return oauthClientId;
    }

    public UserId userId() {
        return userId;
    }

    public TokenHash tokenHash() {
        return tokenHash;
    }

    public Set<String> scopes() {
        return Set.copyOf(scopes);
    }

    public RefreshTokenStatus status() {
        return status;
    }

    public Instant familyExpiresAt() {
        return familyExpiresAt;
    }

    public Instant createdAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof RefreshToken that)) return false;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
