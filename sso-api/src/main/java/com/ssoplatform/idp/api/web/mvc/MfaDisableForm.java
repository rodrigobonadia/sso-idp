package com.ssoplatform.idp.api.web.mvc;

/** Mutable form-backing bean for the {@code account-mfa} Thymeleaf template's disable form. See
 * {@code RegistrationForm} for why this is a plain mutable class rather than a record. */
public class MfaDisableForm {

    private String currentPassword = "";

    public String getCurrentPassword() {
        return currentPassword;
    }

    public void setCurrentPassword(String currentPassword) {
        this.currentPassword = currentPassword;
    }
}
