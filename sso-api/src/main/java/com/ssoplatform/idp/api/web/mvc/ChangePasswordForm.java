package com.ssoplatform.idp.api.web.mvc;

/**
 * Mutable form-backing bean for the {@code change-password} Thymeleaf template's {@code
 * th:object} binding. See {@link RegistrationForm} for why this is a plain mutable class rather
 * than a record.
 */
public class ChangePasswordForm {

    private String currentPassword = "";
    private String newPassword = "";

    public String getCurrentPassword() {
        return currentPassword;
    }

    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
