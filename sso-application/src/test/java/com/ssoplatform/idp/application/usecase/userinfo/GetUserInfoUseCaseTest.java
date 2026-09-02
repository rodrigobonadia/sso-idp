package com.ssoplatform.idp.application.usecase.userinfo;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.InvalidBearerTokenException;
import com.ssoplatform.idp.application.port.out.JwtVerifier;
import com.ssoplatform.idp.application.port.out.SigningKeyRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.domain.signingkey.EncryptedPrivateKeyMaterial;
import com.ssoplatform.idp.domain.signingkey.KeyId;
import com.ssoplatform.idp.domain.signingkey.PublicKeyMaterial;
import com.ssoplatform.idp.domain.signingkey.SigningKey;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.User;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class GetUserInfoUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final TenantId OTHER_TENANT_ID = TenantId.generate();
    private static final String BEARER_TOKEN = "header.payload.signature";

    @Mock
    private SigningKeyRepository signingKeyRepository;

    @Mock
    private JwtVerifier jwtVerifier;

    @Mock
    private UserRepository userRepository;

    private GetUserInfoUseCase useCase;
    private User user;
    private SigningKey signingKey;

    @BeforeEach
    void setUp() {
        useCase = new GetUserInfoUseCase(signingKeyRepository, jwtVerifier, userRepository);
        user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                HashedPassword.of("$2a$10$somehashvalue"));
        signingKey = SigningKey.generate(
                TENANT_ID,
                KeyId.of("kid-1"),
                PublicKeyMaterial.of("cHVibGljLWtleQ=="),
                EncryptedPrivateKeyMaterial.of("ciphertext"));
    }

    /** Only {@link #rejectsABlankBearerToken} never reaches the signing-key lookup - every
     * other test needs this stubbed, so it is opt-in per test rather than in {@link #setUp}
     * to avoid Mockito's strict-stubbing check flagging it as unnecessary there. */
    private void stubSigningKeys() {
        when(signingKeyRepository.findAllByTenantId(TENANT_ID)).thenReturn(List.of(signingKey));
    }

    private Map<String, Object> claimsWithScope(String scope) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", user.id().value().toString());
        claims.put("scope", scope);
        return claims;
    }

    @Test
    void returnsOnlySubWhenScopeGrantsNothingBeyondOpenid() {
        stubSigningKeys();
        when(jwtVerifier.verify(any(), anyMap())).thenReturn(Optional.of(claimsWithScope("openid")));
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));

        UserInfoResult result = useCase.execute(new GetUserInfoCommand(TENANT_ID.value(), BEARER_TOKEN));

        assertThat(result.sub()).isEqualTo(user.id().value().toString());
        assertThat(result.email()).isNull();
        assertThat(result.emailVerified()).isNull();
        assertThat(result.givenName()).isNull();
        assertThat(result.familyName()).isNull();
        assertThat(result.name()).isNull();
    }

    @Test
    void returnsEmailClaimsWhenScopeIncludesEmail() {
        stubSigningKeys();
        when(jwtVerifier.verify(any(), anyMap())).thenReturn(Optional.of(claimsWithScope("openid email")));
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));

        UserInfoResult result = useCase.execute(new GetUserInfoCommand(TENANT_ID.value(), BEARER_TOKEN));

        assertThat(result.email()).isEqualTo("someone@example.com");
        assertThat(result.emailVerified()).isFalse();
        assertThat(result.givenName()).isNull();
    }

    @Test
    void emailVerifiedIsTrueOnceTheAccountHasBeenVerified() {
        stubSigningKeys();
        user.verifyEmail();
        when(jwtVerifier.verify(any(), anyMap())).thenReturn(Optional.of(claimsWithScope("openid email")));
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));

        UserInfoResult result = useCase.execute(new GetUserInfoCommand(TENANT_ID.value(), BEARER_TOKEN));

        assertThat(result.emailVerified()).isTrue();
    }

    @Test
    void returnsProfileClaimsWhenScopeIncludesProfile() {
        stubSigningKeys();
        when(jwtVerifier.verify(any(), anyMap())).thenReturn(Optional.of(claimsWithScope("openid profile")));
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));

        UserInfoResult result = useCase.execute(new GetUserInfoCommand(TENANT_ID.value(), BEARER_TOKEN));

        assertThat(result.givenName()).isEqualTo("Jane");
        assertThat(result.familyName()).isEqualTo("Doe");
        assertThat(result.name()).isEqualTo("Jane Doe");
        assertThat(result.email()).isNull();
    }

    @Test
    void rejectsABlankBearerToken() {
        assertThatThrownBy(() -> useCase.execute(new GetUserInfoCommand(TENANT_ID.value(), " ")))
                .isInstanceOf(InvalidBearerTokenException.class)
                .satisfies(ex -> assertThat(((InvalidBearerTokenException) ex).errorCode()).isEqualTo("invalid_request"));
        verify(jwtVerifier, never()).verify(any(), anyMap());
    }

    @Test
    void rejectsATokenThatFailsSignatureVerification() {
        stubSigningKeys();
        when(jwtVerifier.verify(any(), anyMap())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new GetUserInfoCommand(TENANT_ID.value(), BEARER_TOKEN)))
                .isInstanceOf(InvalidBearerTokenException.class)
                .satisfies(ex -> assertThat(((InvalidBearerTokenException) ex).errorCode()).isEqualTo("invalid_token"));
    }

    @Test
    void rejectsATokenWhoseScopeLacksOpenid() {
        stubSigningKeys();
        when(jwtVerifier.verify(any(), anyMap())).thenReturn(Optional.of(claimsWithScope("email profile")));

        assertThatThrownBy(() -> useCase.execute(new GetUserInfoCommand(TENANT_ID.value(), BEARER_TOKEN)))
                .isInstanceOf(InvalidBearerTokenException.class)
                .satisfies(
                        ex -> assertThat(((InvalidBearerTokenException) ex).errorCode()).isEqualTo("insufficient_scope"));
    }

    @Test
    void rejectsATokenWithAMalformedSubClaim() {
        stubSigningKeys();
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", "not-a-uuid");
        claims.put("scope", "openid");
        when(jwtVerifier.verify(any(), anyMap())).thenReturn(Optional.of(claims));

        assertThatThrownBy(() -> useCase.execute(new GetUserInfoCommand(TENANT_ID.value(), BEARER_TOKEN)))
                .isInstanceOf(InvalidBearerTokenException.class)
                .satisfies(ex -> assertThat(((InvalidBearerTokenException) ex).errorCode()).isEqualTo("invalid_token"));
    }

    @Test
    void rejectsATokenWhoseSubNoLongerResolvesToAUser() {
        stubSigningKeys();
        when(jwtVerifier.verify(any(), anyMap())).thenReturn(Optional.of(claimsWithScope("openid")));
        when(userRepository.findById(user.id())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new GetUserInfoCommand(TENANT_ID.value(), BEARER_TOKEN)))
                .isInstanceOf(InvalidBearerTokenException.class)
                .satisfies(ex -> assertThat(((InvalidBearerTokenException) ex).errorCode()).isEqualTo("invalid_token"));
    }

    @Test
    void rejectsATokenWhoseUserBelongsToAnotherTenant() {
        stubSigningKeys();
        User otherTenantUser = User.register(
                OTHER_TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                HashedPassword.of("$2a$10$somehashvalue"));
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("sub", otherTenantUser.id().value().toString());
        claims.put("scope", "openid");
        when(jwtVerifier.verify(any(), anyMap())).thenReturn(Optional.of(claims));
        when(userRepository.findById(otherTenantUser.id())).thenReturn(Optional.of(otherTenantUser));

        assertThatThrownBy(() -> useCase.execute(new GetUserInfoCommand(TENANT_ID.value(), BEARER_TOKEN)))
                .isInstanceOf(InvalidBearerTokenException.class)
                .satisfies(ex -> assertThat(((InvalidBearerTokenException) ex).errorCode()).isEqualTo("invalid_token"));
    }

    @Test
    void passesEveryTenantSigningKeyAsACandidateVerificationKey() {
        stubSigningKeys();
        when(jwtVerifier.verify(any(), anyMap())).thenReturn(Optional.of(claimsWithScope("openid")));
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));

        useCase.execute(new GetUserInfoCommand(TENANT_ID.value(), BEARER_TOKEN));

        verify(jwtVerifier).verify(eq(BEARER_TOKEN), argThat(map -> map.containsKey(signingKey.kid().value())));
    }
}
