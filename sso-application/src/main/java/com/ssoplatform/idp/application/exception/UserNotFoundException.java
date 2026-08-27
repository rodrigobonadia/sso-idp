package com.ssoplatform.idp.application.exception;

import java.util.UUID;

public class UserNotFoundException extends ApplicationException {

    public UserNotFoundException(UUID userId) {
        super("No user found with id '" + userId + "'");
    }
}
