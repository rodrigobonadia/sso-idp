package com.ssoplatform.idp.api.web.mvc;

/** Mutable form-backing bean for the {@code account-mfa} Thymeleaf template's enrollment-confirm
 * form. See {@code RegistrationForm} for why this is a plain mutable class rather than a record. */
public class MfaConfirmForm {

    private String code = "";

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}
