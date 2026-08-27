package com.ssoplatform.idp.application.usecase.tenant;

/** Input for {@link CreateTenantUseCase}. */
public record CreateTenantCommand(String name, String slug) {}
