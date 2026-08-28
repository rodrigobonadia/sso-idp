package com.ssoplatform.idp.domain.signingkey;

import com.ssoplatform.idp.domain.tenant.TenantId;
import java.time.Instant;
import java.util.Objects;

/**
 * An RSA signing key pair, scoped to exactly one {@link com.ssoplatform.idp.domain.tenant.Tenant}
 * - per the explicit decision that each tenant issues tokens under its own key material, so a
 * tenant's JWKS document (and thus its {@code iss}/token verification) is fully independent of
 * every other tenant's.
 *
 * <p>Rotation is modeled directly on the entity: {@link #retire()} transitions a key from {@link
 * SigningKeyStatus#CURRENT} to {@link SigningKeyStatus#RETIRED} without deleting it - a retired
 * key's {@link #publicKey()} must keep appearing in the tenant's JWKS document so tokens already
 * signed under it remain verifiable, even though {@code GenerateSigningKeyUseCase} (in {@code
 * sso-application}) never signs anything new with it again. Only one key at a time may be {@link
 * SigningKeyStatus#CURRENT} for a given tenant - enforcing that invariant is the use case's job
 * (retire the existing current key, if any, before registering a new one), not this entity's,
 * since it requires looking at every key for the tenant, not just this one.
 *
 * <p>The private key never appears here in plaintext - {@link #encryptedPrivateKey()} is always
 * already encrypted by the time it reaches this entity (see {@link EncryptedPrivateKeyMaterial}).
 */
public final class SigningKey {

    /** The only signing algorithm this platform supports so far - see {@code
     * architecture_decisions.md}, decision (h). Stored per-row (not assumed globally) so a future
     * phase can introduce another algorithm without a schema change. */
    public static final String ALGORITHM = "RS256";

    private final SigningKeyId id;
    private final TenantId tenantId;
    private final KeyId kid;
    private final String algorithm;
    private final PublicKeyMaterial publicKey;
    private final EncryptedPrivateKeyMaterial encryptedPrivateKey;
    private SigningKeyStatus status;
    private final Instant createdAt;

    private SigningKey(
            SigningKeyId id,
            TenantId tenantId,
            KeyId kid,
            String algorithm,
            PublicKeyMaterial publicKey,
            EncryptedPrivateKeyMaterial encryptedPrivateKey,
            SigningKeyStatus status,
            Instant createdAt) {
        this.id = id;
        this.tenantId = tenantId;
        this.kid = kid;
        this.algorithm = algorithm;
        this.publicKey = publicKey;
        this.encryptedPrivateKey = encryptedPrivateKey;
        this.status = status;
        this.createdAt = createdAt;
    }

    /** Registers a brand-new key as the tenant's current signing key. */
    public static SigningKey generate(
            TenantId tenantId, KeyId kid, PublicKeyMaterial publicKey, EncryptedPrivateKeyMaterial encryptedPrivateKey) {
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(kid, "kid must not be null");
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        Objects.requireNonNull(encryptedPrivateKey, "encryptedPrivateKey must not be null");
        return new SigningKey(
                SigningKeyId.generate(),
                tenantId,
                kid,
                ALGORITHM,
                publicKey,
                encryptedPrivateKey,
                SigningKeyStatus.CURRENT,
                Instant.now());
    }

    /** Reconstitutes a key that already exists (used by persistence adapters). */
    public static SigningKey reconstitute(
            SigningKeyId id,
            TenantId tenantId,
            KeyId kid,
            String algorithm,
            PublicKeyMaterial publicKey,
            EncryptedPrivateKeyMaterial encryptedPrivateKey,
            SigningKeyStatus status,
            Instant createdAt) {
        Objects.requireNonNull(id, "id must not be null");
        Objects.requireNonNull(tenantId, "tenantId must not be null");
        Objects.requireNonNull(kid, "kid must not be null");
        if (algorithm == null || algorithm.isBlank()) {
            throw new IllegalArgumentException("algorithm must not be blank");
        }
        Objects.requireNonNull(publicKey, "publicKey must not be null");
        Objects.requireNonNull(encryptedPrivateKey, "encryptedPrivateKey must not be null");
        Objects.requireNonNull(status, "status must not be null");
        Objects.requireNonNull(createdAt, "createdAt must not be null");
        return new SigningKey(id, tenantId, kid, algorithm, publicKey, encryptedPrivateKey, status, createdAt);
    }

    /** Retires this key: it must never sign anything new again, but keeps existing so it can
     * still be published in the JWKS document for verification. */
    public void retire() {
        if (status == SigningKeyStatus.RETIRED) {
            throw new SigningKeyStateException("Signing key '" + kid + "' is already retired");
        }
        this.status = SigningKeyStatus.RETIRED;
    }

    public boolean isCurrent() {
        return status == SigningKeyStatus.CURRENT;
    }

    public SigningKeyId id() {
        return id;
    }

    public TenantId tenantId() {
        return tenantId;
    }

    public KeyId kid() {
        return kid;
    }

    public String algorithm() {
        return algorithm;
    }

    public PublicKeyMaterial publicKey() {
        return publicKey;
    }

    public EncryptedPrivateKeyMaterial encryptedPrivateKey() {
        return encryptedPrivateKey;
    }

    public SigningKeyStatus status() {
        return status;
    }

    public Instant createdAt() {
        return createdAt;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SigningKey that)) return false;
        return id.equals(that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
