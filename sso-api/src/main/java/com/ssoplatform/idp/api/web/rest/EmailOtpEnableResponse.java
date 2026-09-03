package com.ssoplatform.idp.api.web.rest;

/** Response body for {@code POST /api/mfa/email-otp/enable}: a masked form of the address a
 * confirmation code was just sent to - see {@code EnableEmailOtpResult}. */
public record EmailOtpEnableResponse(String maskedEmail) {}
