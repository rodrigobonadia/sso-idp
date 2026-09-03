package com.ssoplatform.idp.api.web.mvc;

/**
 * Mutable form-backing bean for the {@code mfa-challenge} Thymeleaf template's {@code th:object}
 * binding. Carries EITHER a TOTP {@code code} OR a {@code recoveryCode} - never both meaningfully
 * at once - see {@link MfaChallengePageController#submitChallenge} for how the controller picks
 * which factor was actually submitted. See {@code RegistrationForm} for why this is a plain
 * mutable class rather than a record.
 */
public class MfaChallengeForm {

    private String code = "";
    private String recoveryCode = "";

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getRecoveryCode() {
        return recoveryCode;
    }

    public void setRecoveryCode(String recoveryCode) {
        this.recoveryCode = recoveryCode;
    }
}
