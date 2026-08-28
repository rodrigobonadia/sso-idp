package com.ssoplatform.idp.api.web.internal;

import com.ssoplatform.idp.api.web.tenant.TenantContext;
import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.usecase.signingkey.GenerateSigningKeyCommand;
import com.ssoplatform.idp.application.usecase.signingkey.GenerateSigningKeyResult;
import com.ssoplatform.idp.application.usecase.signingkey.GenerateSigningKeyUseCase;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

/**
 * Manual signing-key rotation for the current tenant: {@code POST /internal/signing-keys}
 * generates a brand-new RSA key, makes it the tenant's current signing key, and retires whatever
 * key was current before (see {@link GenerateSigningKeyUseCase}). There is no automatic rotation
 * schedule in this sub-phase - this endpoint is the only way a new key is ever created (see
 * {@code architecture_decisions.md}).
 *
 * <p>Protected only by the application's default {@code anyRequest().authenticated()} rule (any
 * signed-in session for the tenant) - there is no admin role/permission model yet, so this is a
 * deliberate, documented limitation rather than an oversight; see {@code SecurityConfig}'s Javadoc
 * and {@code architecture_decisions.md} for the scope decision behind it.
 */
@RestController
@RequestMapping("/internal")
public class InternalSigningKeyController {

    private final GenerateSigningKeyUseCase generateSigningKeyUseCase;
    private final TenantContext tenantContext;

    public InternalSigningKeyController(
            GenerateSigningKeyUseCase generateSigningKeyUseCase, TenantContext tenantContext) {
        this.generateSigningKeyUseCase = generateSigningKeyUseCase;
        this.tenantContext = tenantContext;
    }

    @PostMapping("/signing-keys")
    @ResponseStatus(HttpStatus.CREATED)
    public GenerateSigningKeyResponse generate() {
        TenantSummary tenant = tenantContext.tenant().orElseThrow(TenantRequiredException::new);
        GenerateSigningKeyResult result =
                generateSigningKeyUseCase.execute(new GenerateSigningKeyCommand(tenant.tenantId()));
        return new GenerateSigningKeyResponse(result.kid(), result.createdAt());
    }
}
