package com.ssoplatform.idp.api.web.mvc;

/**
 * Mutable form-backing bean for the {@code forgot-password} Thymeleaf template's {@code
 * th:object} binding. See {@link RegistrationForm} for why this is a plain mutable class rather
 * than a record.
 */
public class ForgotPasswordForm {

    private String email = "";

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }
}
