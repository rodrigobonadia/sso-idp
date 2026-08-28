package com.ssoplatform.idp.domain.authorization;

import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.domain.verification.VerificationTokenAlreadyConsumedException;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.Set;

/**
 * A single-use, short-lived authorization code issued by {@code GET /authorize} (Phase 3.3) and
 * redeemed by {@code POST /token} (Phase 3.4, not yet built) for an Authorization Code + PKCE
 * grant.
 *
 * <p>Reuses {@link TokenHash} and the consumption exceptions ({@link
 * VerificationTokenAlreadyConsumedException}, {@link VerificationTokenExpiredException}) from
 * {@code domain.verification} rather than defining parallel authorization-code-specific types -
 * exactly the same "purpose-agnostic single-use, high-entropy token" reuse {@code
 * domain.passwordreset.PasswordResetToken} already established in Phase 2.4. The raw code value
 * itself is generated and validated with {@code
 * com.ssoplatform.idp.domain.verification.RawVerificationToken}, for the same reason: a 256-bit
 * random value needs no additional shape rules beyond what that type already enforces.
 *
 * <p>Every field needed to redeem the code safely at {@code /token} time is captured here at issue
 * time, not re-derived later: {@link #redirectUri} must be compared for an EXACT match against the
 * {@code redirect_uri} presented at redemption (RFC 6749 §4.1.3 - a code issued for one redirect
 * URI must never be redeemable against a different one, even a different URI registered to the
 * same client), and {@link #codeChallenge} is what {@code /token} will compare a SHA-256 hash of
 * the caller-supplied {@code code_verifier} against (see {@link CodeChallenge}'s Javadoc for why no
 * "method" field exists - it is always S256).
 */
public final class AuthorizationCode {

    private final AuthorizationCodeId id;
    private final TenantId tenantId;
    private final OAuthClientId oauthClientId;
    private final UserId userId;
    private final TokenHash codeHash;
    private final RedirectUri redirectUri;
    private final Set<String> scopes;
    private final CodeChallenge codeChallenge;
    private final Instant expiresAt;
    private Instant consumedAt;
    private final Instant createdAt;

    private AuthorizationCode(
            AuthorizationCodeId id,
            TenantId tenantId,
            OAuthClientId oauthClientId,
            UserId userId,
            TokenHash codeHash,
            RedirectUri redirectUri,
            Set<String> scopes,
            CodeChallenge codeChallenge,
            Instant expiresAt,
            Instant consumedAt,
            Instant createdAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.oauthClientId = oauthClientId;
        this.userId = userId;
        this.codeHash = codeHash;
        this.redirectUri = redirectUri;
        this.scopes = scopes;
        this.codeChallenge = codeChallenge;
        this.expiresAt = expiresAt;
        this.consumedAt = consumedAt;
        this.createdAt = createdAt;
    }

    /** Issues a brand-new, unconsumed code, valid from {@code now} for {@code validity}. */
    public static AuthorizationCode issue(
            TenantId tenantId,
            OAuthClientId oauthClientId,
            UserId userId,
            TokenHash codeHash,
            RedirectUri redirectUri,
            Set<String> scopes,
            CodeChallenge codeChallenge,
            Instant now,
            Duration validity) {
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(oauthClientId, "oauthClientId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(codeHash, "codeHash must not be null");
        Objects.requireNonNull(redirectUri, "redirectUri must not be null");
        Objects.requireNonNull(scopes, "scopes must not be null");
        if (scopes.isEmpty()) {
            throw new IllegalArgumentException("An authorization code must carry at least one scope");
        }
        Objects.requireNonNull(codeChallenge, "codeChallenge must not be null");
        Objects.requireNonNull(now, "now must not be null");
        Objects.requireNonNull(validity, "validity must not be null");
        return new AuthorizationCode(
                AuthorizationCodeId.generate(),
                tenantId,
                oauthClientId,
                userId,
                codeHash,
                redirectUri,
                Set.copyOf(scopes),
                codeChallenge,
                now.plus(validity),
                null,
                now);
    }

    /** Reconstitutes a code that already exists (used by persistence adapters). */
    public static AuthorizationCode reconstitute(
            AuthorizationCodeId id,
            TenantId tenantId,
            OAuthClientId oauthClientId,
            UserId userId,
            TokenHash codeHash,
            RedirectUri redirectUri,
            Set<String> scopes,
            CodeChallenge codeChallenge,
            Instant expiresAt,
            Instant consumedAt,
            Instant createdAt) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(oauthClientId, "oauthClientId must not be null");
        Objects.requireNonNull(userId, "userId must not be null");
        Objects.requireNonNull(codeHash, "codeHash must not be null");
        Objects.requireNonNull(redirectUri, "redirectUri must not be null");
        Objects.requireNonNull(scopes, "scopes must not be null");
        Objects.requireNonNull(codeChallenge, "codeChallenge must not be null");
        Objects.requireNonNull(expiresAt, "expiresAt must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        return new AuthorizationCode(
                id,
                tenantId,
                oauthClientId,
                userId,
                codeHash,
                redirectUri,
                Set.copyOf(scopes),
                codeChallenge,
                expiresAt,
                consumedAt,
                createdAt);
    }

    /**
     * Marks the code as redeemed. Not called by any use case in Phase 3.3 (this sub-phase only
     * ISSUES codes) - included now so the entity's full lifecycle is already modeled for {@code
     * /token} (Phase 3.4) to call without any shape change, exactly like {@link
     * com.ssoplatform.idp.domain.oauth.OAuthClientRepository#save} was added in Phase 3.1 ahead of
     * its first real caller.
     */
    public void consume(Instant now) {
        Objects.requireNonNull(now, "now must not be null");
        if (isConsumed()) {
            throw new VerificationTokenAlreadyConsumedException();
        }
        if (isExpired(now)) {
            throw new VerificationTokenExpiredException();
        }
        this.consumedAt = now;
    }

    public boolean isConsumed() {
        return consumedAt != null;
    }

    public boolean isExpired(Instant now) {
        return now.isAfter(expiresAt);
    }

    public AuthorizationCodeId id() {
        return id;
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

    public TokenHash codeHash() {
        return codeHash;
    }

    public RedirectUri redirectUri() {
        return redirectUri;
    }

    public Set<String> scopes() {
        return Set.copyOf(scopes);
    }

    public CodeChallenge codeChallenge() {
        return codeChallenge;
    }

    public Instant expiresAt() {
        return expiresAt;
    }

    public Instant consumedAt() {
        return consumedAt;
    }

    public Instant createdAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AuthorizationCode that)) return false;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
