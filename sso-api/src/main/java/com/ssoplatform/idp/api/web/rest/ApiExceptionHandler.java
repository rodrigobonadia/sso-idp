package com.ssoplatform.idp.api.web.rest;

import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.exception.AccountDisabledException;
import com.ssoplatform.idp.application.exception.AccountLockedException;
import com.ssoplatform.idp.application.exception.AccountNotVerifiedException;
import com.ssoplatform.idp.application.exception.DuplicateEmailException;
import com.ssoplatform.idp.application.exception.IncorrectCurrentPasswordException;
import com.ssoplatform.idp.application.exception.InvalidCredentialsException;
import com.ssoplatform.idp.application.exception.InvalidMfaCodeException;
import com.ssoplatform.idp.application.exception.MfaAlreadyEnabledException;
import com.ssoplatform.idp.application.exception.MfaEnrollmentNotFoundException;
import com.ssoplatform.idp.application.exception.MfaNotEnabledException;
import com.ssoplatform.idp.application.exception.TenantNotActiveException;
import com.ssoplatform.idp.application.exception.TenantNotFoundException;
import com.ssoplatform.idp.application.exception.VerificationTokenNotFoundException;
import com.ssoplatform.idp.domain.mfa.InvalidEmailOtpCodeException;
import com.ssoplatform.idp.domain.mfa.InvalidRecoveryCodeException;
import com.ssoplatform.idp.domain.mfa.InvalidTotpCodeException;
import com.ssoplatform.idp.domain.mfa.TooManyFailedEmailOtpAttemptsException;
import com.ssoplatform.idp.domain.user.InvalidEmailException;
import com.ssoplatform.idp.domain.user.UserStateException;
import com.ssoplatform.idp.domain.user.WeakPasswordException;
import com.ssoplatform.idp.domain.verification.InvalidVerificationTokenException;
import com.ssoplatform.idp.domain.verification.VerificationTokenAlreadyConsumedException;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Translates application/domain exceptions into HTTP responses, scoped only to the JSON-returning
 * controller packages ({@code web.rest}, plus {@code web.oidc} and {@code web.internal} added in
 * Phase 3.2 for the JWKS and signing-key-generation endpoints) - the MVC controllers under
 * {@code web.mvc} render these same exceptions as HTML pages instead (see {@code
 * RegistrationPageController}), so a shared, unscoped {@code @RestControllerAdvice} would be the
 * wrong tool for either surface.
 */
@RestControllerAdvice(
        basePackages = {
            "com.ssoplatform.idp.api.web.rest",
            "com.ssoplatform.idp.api.web.oidc",
            "com.ssoplatform.idp.api.web.internal"
        })
public class ApiExceptionHandler {

    @ExceptionHandler(DuplicateEmailException.class)
    public ResponseEntity<ErrorResponse> handleConflict(DuplicateEmailException ex) {
        return respond(HttpStatus.CONFLICT, ex);
    }

    @ExceptionHandler(VerificationTokenAlreadyConsumedException.class)
    public ResponseEntity<ErrorResponse> handleConflict(VerificationTokenAlreadyConsumedException ex) {
        return respond(HttpStatus.CONFLICT, ex);
    }

    @ExceptionHandler({
        WeakPasswordException.class,
        InvalidEmailException.class,
        InvalidVerificationTokenException.class,
        TenantRequiredException.class,
        IncorrectCurrentPasswordException.class,
        InvalidTotpCodeException.class,
        InvalidRecoveryCodeException.class,
        InvalidEmailOtpCodeException.class
    })
    public ResponseEntity<ErrorResponse> handleBadRequest(RuntimeException ex) {
        return respond(HttpStatus.BAD_REQUEST, ex);
    }

    @ExceptionHandler({
        TenantNotFoundException.class,
        VerificationTokenNotFoundException.class,
        MfaEnrollmentNotFoundException.class,
        MfaNotEnabledException.class
    })
    public ResponseEntity<ErrorResponse> handleNotFound(RuntimeException ex) {
        return respond(HttpStatus.NOT_FOUND, ex);
    }

    @ExceptionHandler(MfaAlreadyEnabledException.class)
    public ResponseEntity<ErrorResponse> handleConflict(MfaAlreadyEnabledException ex) {
        return respond(HttpStatus.CONFLICT, ex);
    }

    @ExceptionHandler(InvalidMfaCodeException.class)
    public ResponseEntity<ErrorResponse> handleUnauthorized(InvalidMfaCodeException ex) {
        return respond(HttpStatus.UNAUTHORIZED, ex);
    }

    /**
     * A live but permanently-exhausted e-mail OTP code (Phase 4.2) - see {@code EmailOtpCode}'s
     * Javadoc for why this limit exists at all. {@code 429 Too Many Requests} (RFC 6585) is the
     * semantically correct status for "you have made too many attempts, try again by requesting a
     * new code" - distinct from {@code 401} (a single wrong code that can still be retried) and
     * from {@code 410 Gone} (a code that expired from elapsed time rather than attempt count).
     */
    @ExceptionHandler(TooManyFailedEmailOtpAttemptsException.class)
    public ResponseEntity<ErrorResponse> handleTooManyRequests(TooManyFailedEmailOtpAttemptsException ex) {
        return respond(HttpStatus.TOO_MANY_REQUESTS, ex);
    }

    @ExceptionHandler(TenantNotActiveException.class)
    public ResponseEntity<ErrorResponse> handleForbidden(TenantNotActiveException ex) {
        return respond(HttpStatus.FORBIDDEN, ex);
    }

    @ExceptionHandler(VerificationTokenExpiredException.class)
    public ResponseEntity<ErrorResponse> handleGone(VerificationTokenExpiredException ex) {
        return respond(HttpStatus.GONE, ex);
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleUnauthorized(InvalidCredentialsException ex) {
        return respond(HttpStatus.UNAUTHORIZED, ex);
    }

    @ExceptionHandler({
        AccountNotVerifiedException.class,
        AccountLockedException.class,
        AccountDisabledException.class,
        UserStateException.class
    })
    public ResponseEntity<ErrorResponse> handleAccountNotUsable(RuntimeException ex) {
        return respond(HttpStatus.FORBIDDEN, ex);
    }

    private ResponseEntity<ErrorResponse> respond(HttpStatus status, RuntimeException ex) {
        return ResponseEntity.status(status).body(new ErrorResponse(ex.getMessage()));
    }
}
