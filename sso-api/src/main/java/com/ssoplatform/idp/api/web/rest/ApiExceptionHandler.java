package com.ssoplatform.idp.api.web.rest;

import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.exception.DuplicateEmailException;
import com.ssoplatform.idp.application.exception.TenantNotActiveException;
import com.ssoplatform.idp.application.exception.TenantNotFoundException;
import com.ssoplatform.idp.application.exception.VerificationTokenNotFoundException;
import com.ssoplatform.idp.domain.user.InvalidEmailException;
import com.ssoplatform.idp.domain.user.WeakPasswordException;
import com.ssoplatform.idp.domain.verification.InvalidVerificationTokenException;
import com.ssoplatform.idp.domain.verification.VerificationTokenAlreadyConsumedException;
import com.ssoplatform.idp.domain.verification.VerificationTokenExpiredException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * Translates application/domain exceptions into HTTP responses, scoped only to
 * {@code web.rest} controllers - the MVC controllers under {@code web.mvc} render these same
 * exceptions as HTML pages instead (see {@code RegistrationPageController}), so a shared,
 * unscoped {@code @RestControllerAdvice} would be the wrong tool for either surface.
 */
@RestControllerAdvice(basePackages = "com.ssoplatform.idp.api.web.rest")
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
        TenantRequiredException.class
    })
    public ResponseEntity<ErrorResponse> handleBadRequest(RuntimeException ex) {
        return respond(HttpStatus.BAD_REQUEST, ex);
    }

    @ExceptionHandler({TenantNotFoundException.class, VerificationTokenNotFoundException.class})
    public ResponseEntity<ErrorResponse> handleNotFound(RuntimeException ex) {
        return respond(HttpStatus.NOT_FOUND, ex);
    }

    @ExceptionHandler(TenantNotActiveException.class)
    public ResponseEntity<ErrorResponse> handleForbidden(TenantNotActiveException ex) {
        return respond(HttpStatus.FORBIDDEN, ex);
    }

    @ExceptionHandler(VerificationTokenExpiredException.class)
    public ResponseEntity<ErrorResponse> handleGone(VerificationTokenExpiredException ex) {
        return respond(HttpStatus.GONE, ex);
    }

    private ResponseEntity<ErrorResponse> respond(HttpStatus status, RuntimeException ex) {
        return ResponseEntity.status(status).body(new ErrorResponse(ex.getMessage()));
    }
}
