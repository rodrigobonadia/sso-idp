package com.ssoplatform.idp.domain.devicecode;

/**
 * The lifecycle of a {@link DeviceCode} (RFC 8628): {@code PENDING} from the moment the device
 * requests it, then either {@code APPROVED} or {@code DENIED} once a user acts on the
 * verification page, and finally {@code REDEEMED} once the device successfully polls {@code
 * /token} and receives its tokens - see {@link DeviceCode}'s Javadoc for the full transition
 * rules. Unlike {@code AuthorizationCode}, which collapses its lifecycle into a single {@code
 * consumedAt} timestamp because both of its terminal outcomes map to the same {@code
 * invalid_grant} error, this status is read directly by {@code TokenUseCase} to select between
 * four different RFC 8628 {@code /token} error codes ({@code authorization_pending}, {@code
 * access_denied}, {@code invalid_grant}, or success).
 */
public enum DeviceCodeStatus {
    PENDING,
    APPROVED,
    DENIED,
    REDEEMED
}
