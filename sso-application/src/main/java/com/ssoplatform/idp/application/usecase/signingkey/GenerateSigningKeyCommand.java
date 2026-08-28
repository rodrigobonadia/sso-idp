package com.ssoplatform.idp.application.usecase.signingkey;

import java.util.UUID;

public record GenerateSigningKeyCommand(UUID tenantId) {}
