package com.ssoplatform.idp.api.web.mvc;

/**
 * Mutable form-backing bean for the {@code login} Thymeleaf template's {@code th:object} binding.
 * See {@link RegistrationForm} for why this is a plain mutable class rather than a record.
 */
public class LoginForm {

    private String email = "";
    private String password = "";

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
