package com.ssoplatform.idp.api.web.internal;

import java.time.Instant;

/** Never carries any key material, public or private - only enough to confirm a new key was
 * generated and identify it (e.g. for correlating with logs). */
public record GenerateSigningKeyResponse(String kid, Instant createdAt) {}
