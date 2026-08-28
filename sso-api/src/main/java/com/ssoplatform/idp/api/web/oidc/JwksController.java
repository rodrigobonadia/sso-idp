package com.ssoplatform.idp.api.web.oidc;

import com.ssoplatform.idp.api.web.tenant.TenantContext;
import com.ssoplatform.idp.api.web.tenant.TenantRequiredException;
import com.ssoplatform.idp.application.usecase.signingkey.ListSigningKeysQuery;
import com.ssoplatform.idp.application.usecase.signingkey.ListSigningKeysUseCase;
import com.ssoplatform.idp.application.usecase.signingkey.SigningKeySummary;
import com.ssoplatform.idp.application.usecase.tenant.TenantSummary;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Publishes the current tenant's JWKS document at the standard OIDC discovery path, {@code
 * /.well-known/jwks.json} - one entry per {@link SigningKeySummary} returned by {@link
 * ListSigningKeysUseCase}, current and retired alike (see that use case's Javadoc for why retired
 * keys are still published). Deliberately public ({@code permitAll} in {@code SecurityConfig}):
 * a JWKS document exists to be fetched by anyone verifying a token, so it can never require
 * authentication.
 *
 * <p>Per-tenant, exactly like every other OAuth2/OIDC surface in this project so far: the request
 * must resolve to a tenant via its subdomain (see {@code TenantResolutionFilter}), or this
 * endpoint responds the same {@code TenantRequiredException} (400) every other tenant-scoped
 * endpoint does for a root-domain request.
 */
@RestController
public class JwksController {

    private final ListSigningKeysUseCase listSigningKeysUseCase;
    private final TenantContext tenantContext;

    public JwksController(ListSigningKeysUseCase listSigningKeysUseCase, TenantContext tenantContext) {
        this.listSigningKeysUseCase = listSigningKeysUseCase;
        this.tenantContext = tenantContext;
    }

    @GetMapping("/.well-known/jwks.json")
    public JwksResponse jwks() {
        TenantSummary tenant = tenantContext.tenant().orElseThrow(TenantRequiredException::new);
        List<SigningKeySummary> keys =
                listSigningKeysUseCase.execute(new ListSigningKeysQuery(tenant.tenantId()));
        return new JwksResponse(keys.stream().map(JwksController::toJwk).toList());
    }

    private static JwkResponse toJwk(SigningKeySummary key) {
        RSAPublicKey publicKey = decodeRsaPublicKey(key.publicKeyDer());
        String n = base64Url(toUnsignedBytes(publicKey.getModulus()));
        String e = base64Url(toUnsignedBytes(publicKey.getPublicExponent()));
        return new JwkResponse("RSA", "sig", key.algorithm(), key.kid(), n, e);
    }

    private static RSAPublicKey decodeRsaPublicKey(String base64EncodedDer) {
        try {
            byte[] der = Base64.getDecoder().decode(base64EncodedDer);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(der));
        } catch (Exception e) {
            // Public key material is only ever written by GenerateSigningKeyUseCase itself, so a
            // failure here would indicate stored data corruption, not a caller-supplied error.
            throw new IllegalStateException("Stored public key material could not be decoded", e);
        }
    }

    /** {@code BigInteger.toByteArray()} may prepend a leading zero byte to keep the value
     * unambiguously positive in two's-complement form - a JWK's {@code n}/{@code e} fields must
     * not carry that sign byte, so it is stripped here before Base64url-encoding. */
    private static byte[] toUnsignedBytes(BigInteger value) {
        byte[] bytes = value.toByteArray();
        if (bytes.length > 1 && bytes[0] == 0) {
            return Arrays.copyOfRange(bytes, 1, bytes.length);
        }
        return bytes;
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
