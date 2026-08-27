package com.ssoplatform.idp.api.web.mvc;

/**
 * Mutable form-backing bean for the {@code register} Thymeleaf template's {@code th:object}
 * binding. Deliberately a plain mutable class rather than a record: Spring's data binder
 * populates it via setters reflectively from request parameters, which records - being
 * immutable and constructor-only - cannot support.
 */
public class RegistrationForm {

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
