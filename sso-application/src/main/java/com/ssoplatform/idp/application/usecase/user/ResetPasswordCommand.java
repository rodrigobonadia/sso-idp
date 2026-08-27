package com.ssoplatform.idp.application.usecase.user;

/** Input for {@link ResetPasswordUseCase}. Not tenant-scoped: the token itself already uniquely
 * identifies the user being reset, regardless of which subdomain the request came in on - the
 * same reason {@link VerifyEmailCommand} isn't tenant-scoped either. */
public record ResetPasswordCommand(String rawToken, String newRawPassword) {}
