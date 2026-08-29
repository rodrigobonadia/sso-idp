package com.ssoplatform.idp.application.port.out;

import com.ssoplatform.idp.domain.authorization.CodeChallenge;

/**
 * Output port that hides the concrete PKCE verification transform (RFC 7636 §4.6) from the
 * application layer. Implemented in {@code sso-infrastructure}.
 *
 * <p>Only ever checks the {@code S256} transform - see {@link CodeChallenge}'s Javadoc for why
 * {@code plain} is never modeled at all, at either {@code /authorize} or {@code /token}. {@link
 * #matches} takes the caller-supplied {@code code_verifier} and the {@link CodeChallenge} value
 * that was captured at {@code /authorize} time, and reports whether {@code
 * BASE64URL(SHA256(code_verifier))} equals it - the exact check RFC 7636 §4.6 defines.
 */
public interface CodeVerifierValidator {

    boolean matches(String codeVerifier, CodeChallenge codeChallenge);
}
