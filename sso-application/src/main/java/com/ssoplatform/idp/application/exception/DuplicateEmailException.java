package com.ssoplatform.idp.application.exception;

public class DuplicateEmailException extends ApplicationException {

    public DuplicateEmailException(String email) {
        super("A user with email '" + email + "' already exists for this tenant");
    }
}
