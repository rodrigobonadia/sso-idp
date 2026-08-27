package com.ssoplatform.idp.api.web.mvc;

/**
 * Mutable form-backing bean for the {@code reset-password} Thymeleaf template's {@code
 * th:object} binding. Carries the token as a hidden field (round-tripped from the {@code ?token=}
 * query parameter that landed the user on the form) alongside the new password. See {@link
 * RegistrationForm} for why this is a plain mutable class rather than a record.
 */
public class ResetPasswordForm {

    private String token = "";
    private String newPassword = "";

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
