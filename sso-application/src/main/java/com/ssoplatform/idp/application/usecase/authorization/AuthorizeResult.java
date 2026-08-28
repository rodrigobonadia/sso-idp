package com.ssoplatform.idp.application.usecase.authorization;

/**
 * Output of a successful {@link AuthorizeUseCase#execute}: the raw authorization code value (never
 * persisted itself - only its hash is, see {@code AuthorizationCode} - so this is the one and only
 * moment the plaintext code exists outside the client's redirect), the exact {@code redirect_uri}
 * to send the resource owner's browser back to, and the original {@code state} value to echo back
 * unchanged (RFC 6749 §4.1.2 - lets the client correlate the response with its original request and
 * detect CSRF). {@code AuthorizeController} builds the final {@code redirect_uri?code=...&state=...}
 * URL from these three fields.
 */
public record AuthorizeResult(String code, String redirectUri, String state) {}
