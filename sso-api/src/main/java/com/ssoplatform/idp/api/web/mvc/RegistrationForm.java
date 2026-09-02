package com.ssoplatform.idp.api.web.mvc;

/**
 * Mutable form-backing bean for the {@code register} Thymeleaf template's {@code th:object}
 * binding. Deliberately a plain mutable class rather than a record: Spring's data binder
 * populates it via setters reflectively from request parameters, which records - being
 * immutable and constructor-only - cannot support.
 */
public class RegistrationForm {

    private String email = "";
    private String givenName = "";
    private String familyName = "";
    private String password = "";

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getGivenName() {
        return givenName;
    }

    public void setGivenName(String givenName) {
        this.givenName = givenName;
    }

    public String getFamilyName() {
        return familyName;
    }

    public void setFamilyName(String familyName) {
        this.familyName = familyName;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }
}
