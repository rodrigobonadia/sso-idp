package com.ssoplatform.idp.domain.refreshtoken;

import com.ssoplatform.idp.domain.shared.DomainException;

/**
 * Raised when a refresh token that is no longer {@link RefreshTokenStatus#ACTIVE} - i.e. one that
 * was already rotated or already revoked - is presented for redemption again.
 *
 * <p>Deliberately distinct from {@code VerificationTokenAlreadyConsumedException}: that exception
 * models an ordinary single-use token being redeemed twice, which is just a client error. This
 * exception models a ROTATED token being presented again, which - because rotation means a newer,
 * still-active token already exists for this family - is treated as a theft signal rather than a
 * simple retry. Catching this exception is what should trigger revocation of the entire token
 * family (see {@code TokenUseCase.executeRefreshTokenGrant}), not just rejection of this one
 * request.
 */
public class RefreshTokenReusedException extends DomainException {

    public RefreshTokenReusedException() {
        super("Refresh token has already been rotated or revoked");
    }
}
