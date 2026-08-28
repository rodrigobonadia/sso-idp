package com.ssoplatform.idp.application.usecase.signingkey;

import java.time.Instant;
import java.util.UUID;

/** Never carries any key material, public or private - only the identifiers a caller needs to
 * confirm a new key was generated. */
public record GenerateSigningKeyResult(String kid, UUID tenantId, Instant createdAt) {}
