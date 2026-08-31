package com.ssoplatform.idp.domain.refreshtoken;

/**
 * Lifecycle state of a single {@link RefreshToken} row.
 *
 * <ul>
 *   <li>{@link #ACTIVE} - the currently valid token for its family; the only status {@link
 *       RefreshToken#rotate(java.time.Instant)} may be called on.
 *   <li>{@link #ROTATED} - this exact value was already redeemed once and replaced by the next
 *       token in the family. Presenting a {@code ROTATED} token again is the reuse signal that
 *       triggers full-family revocation.
 *   <li>{@link #REVOKED} - explicitly invalidated, either directly or as part of a full-family
 *       revocation sweep triggered by reuse detection on any member of the family.
 * </ul>
 */
public enum RefreshTokenStatus {
    ACTIVE,
    ROTATED,
    REVOKED
}
