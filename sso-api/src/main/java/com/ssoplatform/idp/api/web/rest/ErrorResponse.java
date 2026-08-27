package com.ssoplatform.idp.api.web.rest;

/** Uniform error body returned by {@link ApiExceptionHandler} for every mapped failure. */
public record ErrorResponse(String error) {}
