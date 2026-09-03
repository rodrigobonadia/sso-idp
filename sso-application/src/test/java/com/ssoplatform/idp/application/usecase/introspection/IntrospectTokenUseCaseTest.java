package com.ssoplatform.idp.application.usecase.introspection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.OAuthIntrospectionException;
import com.ssoplatform.idp.application.port.out.ClientSecretHasher;
import com.ssoplatform.idp.application.port.out.JwtVerifier;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.application.port.out.RefreshTokenRepository;
import com.ssoplatform.idp.application.port.out.SigningKeyRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.ClientSecretHash;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.refreshtoken.RefreshToken;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class IntrospectTokenUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final TenantId OTHER_TENANT_ID = TenantId.generate();
    private static final String CLIENT_SECRET = "s3cr3t-value";

    @Mock
    private OAuthClientRepository oauthClientRepository;

    @Mock
    private ClientSecretHasher clientSecretHasher;

    @Mock
    private SigningKeyRepository signingKeyRepository;

    @Mock
    private JwtVerifier jwtVerifier;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private VerificationTokenHasher verificationTokenHasher;

    private IntrospectTokenUseCase useCase;
    private OAuthClient confidentialClient;

    @BeforeEach
    void setUp() {
        useCase = new IntrospectTokenUseCase(
                oauthClientRepository,
                clientSecretHasher,
                signingKeyRepository,
                jwtVerifier,
                refreshTokenRepository,
                verificationTokenHasher);
        confidentialClient = OAuthClient.register(
                TENANT_ID,
                ClientId.of("acme-test-app"),
                ClientSecretHash.of("stored-hash"),
                "Acme Test App",
                Set.of(RedirectUri.of("https://app.example.com/callback")),
                Set.of("openid", "profile"),
                Set.of(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN));
    }

    private IntrospectTokenCommand command(String token) {
        return new IntrospectTokenCommand(TENANT_ID.value(), token, null, "acme-test-app", CLIENT_SECRET);
    }

    private void stubSuccessfulClientAuth() {
        when(oauthClientRepository.findByClientId(ClientId.of("acme-test-app")))
                .thenReturn(Optional.of(confidentialClient));
        when(clientSecretHasher.matches(CLIENT_SECRET, confidentialClient.clientSecretHash())).thenReturn(true);
    }

    private static Map<String, Object> accessTokenClaims(String clientId, long exp) {
        Map<String, Object> claims = new LinkedHashMap<>();
        claims.put("iss", "http://acme.localhost:8080");
        claims.put("sub", "b7faa990-c5d9-4bf6-996a-28048ea9b4a5");
        claims.put("aud", clientId);
        claims.put("client_id", clientId);
        claims.put("iat", exp - 900);
        claims.put("exp", exp);
        claims.put("jti", "a-jti-value");
        claims.put("scope", "openid profile");
        return claims;
    }

    @Test
    void introspectsAValidAccessTokenAndReturnsItsClaims() {
        stubSuccessfulClientAuth();
        long exp = Instant.now().plusSeconds(900).getEpochSecond();
        when(jwtVerifier.verify(anyString(), any())).thenReturn(Optional.of(accessTokenClaims("acme-test-app", exp)));

        IntrospectTokenResult result = useCase.execute(command("some.jwt.value"));

        assertThat(result.active()).isTrue();
        assertThat(result.clientId()).isEqualTo("acme-test-app");
        assertThat(result.tokenType()).isEqualTo("Bearer");
        assertThat(result.scope()).isEqualTo("openid profile");
        assertThat(result.exp()).isEqualTo(exp);
        assertThat(result.jti()).isEqualTo("a-jti-value");
    }

    @Test
    void reportsInactiveForAnAccessTokenIssuedToADifferentClient() {
        stubSuccessfulClientAuth();
        long exp = Instant.now().plusSeconds(900).getEpochSecond();
        when(jwtVerifier.verify(anyString(), any()))
                .thenReturn(Optional.of(accessTokenClaims("some-other-client", exp)));

        // "some.jwt.value" is JWT-shaped (contains dots), so the fallback tryAsRefreshToken() call
        // short-circuits inside RawVerificationToken.of() before ever touching
        // verificationTokenHasher/refreshTokenRepository - no need to stub them here.
        IntrospectTokenResult result = useCase.execute(command("some.jwt.value"));

        assertThat(result.active()).isFalse();
    }

    @Test
    void doesNotTreatAnIdTokenAsIntrospectable() {
        stubSuccessfulClientAuth();
        Map<String, Object> idTokenClaims = new LinkedHashMap<>();
        idTokenClaims.put("iss", "http://acme.localhost:8080");
        idTokenClaims.put("sub", "b7faa990-c5d9-4bf6-996a-28048ea9b4a5");
        idTokenClaims.put("aud", "acme-test-app");
        idTokenClaims.put("iat", Instant.now().getEpochSecond());
        idTokenClaims.put("exp", Instant.now().plusSeconds(900).getEpochSecond());
        when(jwtVerifier.verify(anyString(), any())).thenReturn(Optional.of(idTokenClaims));

        // "some.id.jwt" is JWT-shaped (contains dots), so the fallback tryAsRefreshToken() call
        // short-circuits inside RawVerificationToken.of() before ever touching
        // verificationTokenHasher/refreshTokenRepository - no need to stub them here.
        IntrospectTokenResult result = useCase.execute(command("some.id.jwt"));

        assertThat(result.active()).isFalse();
    }

    private void stubRefreshTokenMiss() {
        when(verificationTokenHasher.hash(any())).thenReturn(TokenHash.of("some-hash"));
        when(refreshTokenRepository.findByTokenHash(any())).thenReturn(Optional.empty());
    }

    @Test
    void introspectsAValidRefreshTokenAndReturnsItsClaims() {
        stubSuccessfulClientAuth();
        when(jwtVerifier.verify(anyString(), any())).thenReturn(Optional.empty());
        TokenHash hash = TokenHash.of("refresh-hash");
        when(verificationTokenHasher.hash(any())).thenReturn(hash);
        UserId userId = UserId.generate();
        RefreshToken refreshToken = RefreshToken.issueFirst(
                TENANT_ID, confidentialClient.id(), userId, hash, Set.of("openid", "offline_access"), Instant.now(),
                Duration.ofDays(30));
        when(refreshTokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(refreshToken));

        IntrospectTokenResult result = useCase.execute(command("raw-refresh-token-value"));

        assertThat(result.active()).isTrue();
        assertThat(result.clientId()).isEqualTo("acme-test-app");
        assertThat(result.tokenType()).isEqualTo("refresh_token");
        assertThat(result.scope().split(" ")).containsExactlyInAnyOrder("openid", "offline_access");
        assertThat(result.sub()).isEqualTo(userId.value().toString());
        assertThat(result.jti()).isEqualTo(refreshToken.id().value().toString());
    }

    @Test
    void reportsInactiveForARefreshTokenBelongingToAnotherClient() {
        stubSuccessfulClientAuth();
        when(jwtVerifier.verify(anyString(), any())).thenReturn(Optional.empty());
        TokenHash hash = TokenHash.of("refresh-hash");
        when(verificationTokenHasher.hash(any())).thenReturn(hash);
        RefreshToken refreshToken = RefreshToken.issueFirst(
                TENANT_ID,
                com.ssoplatform.idp.domain.oauth.OAuthClientId.generate(),
                UserId.generate(),
                hash,
                Set.of("openid"),
                Instant.now(),
                Duration.ofDays(30));
        when(refreshTokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(refreshToken));

        IntrospectTokenResult result = useCase.execute(command("raw-refresh-token-value"));

        assertThat(result.active()).isFalse();
    }

    @Test
    void reportsInactiveForARefreshTokenBelongingToAnotherTenant() {
        stubSuccessfulClientAuth();
        when(jwtVerifier.verify(anyString(), any())).thenReturn(Optional.empty());
        TokenHash hash = TokenHash.of("refresh-hash");
        when(verificationTokenHasher.hash(any())).thenReturn(hash);
        RefreshToken refreshToken = RefreshToken.issueFirst(
                OTHER_TENANT_ID, confidentialClient.id(), UserId.generate(), hash, Set.of("openid"), Instant.now(),
                Duration.ofDays(30));
        when(refreshTokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(refreshToken));

        IntrospectTokenResult result = useCase.execute(command("raw-refresh-token-value"));

        assertThat(result.active()).isFalse();
    }

    @Test
    void reportsInactiveForARevokedRefreshToken() {
        stubSuccessfulClientAuth();
        when(jwtVerifier.verify(anyString(), any())).thenReturn(Optional.empty());
        TokenHash hash = TokenHash.of("refresh-hash");
        when(verificationTokenHasher.hash(any())).thenReturn(hash);
        RefreshToken refreshToken = RefreshToken.issueFirst(
                TENANT_ID, confidentialClient.id(), UserId.generate(), hash, Set.of("openid"), Instant.now(),
                Duration.ofDays(30));
        refreshToken.revoke();
        when(refreshTokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(refreshToken));

        IntrospectTokenResult result = useCase.execute(command("raw-refresh-token-value"));

        assertThat(result.active()).isFalse();
    }

    @Test
    void reportsInactiveForAnExpiredRefreshToken() {
        stubSuccessfulClientAuth();
        when(jwtVerifier.verify(anyString(), any())).thenReturn(Optional.empty());
        TokenHash hash = TokenHash.of("refresh-hash");
        when(verificationTokenHasher.hash(any())).thenReturn(hash);
        RefreshToken refreshToken = RefreshToken.issueFirst(
                TENANT_ID,
                confidentialClient.id(),
                UserId.generate(),
                hash,
                Set.of("openid"),
                Instant.now().minus(Duration.ofDays(31)),
                Duration.ofDays(30));
        when(refreshTokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(refreshToken));

        IntrospectTokenResult result = useCase.execute(command("raw-refresh-token-value"));

        assertThat(result.active()).isFalse();
    }

    @Test
    void reportsInactiveForACompletelyUnknownToken() {
        stubSuccessfulClientAuth();
        when(jwtVerifier.verify(anyString(), any())).thenReturn(Optional.empty());
        stubRefreshTokenMiss();

        IntrospectTokenResult result = useCase.execute(command("garbage-not-a-real-token"));

        assertThat(result.active()).isFalse();
    }

    @Test
    void rejectsABlankToken() {
        stubSuccessfulClientAuth();

        assertThatThrownBy(() -> useCase.execute(command("  ")))
                .isInstanceOf(OAuthIntrospectionException.class)
                .satisfies(ex -> assertThat(((OAuthIntrospectionException) ex).errorCode()).isEqualTo("invalid_request"));
        verify(jwtVerifier, never()).verify(anyString(), any());
    }

    @Test
    void rejectsMissingClientCredentials() {
        IntrospectTokenCommand command = new IntrospectTokenCommand(TENANT_ID.value(), "a-token", null, null, null);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthIntrospectionException.class)
                .satisfies(ex -> assertThat(((OAuthIntrospectionException) ex).errorCode()).isEqualTo("invalid_client"));
        verify(oauthClientRepository, never()).findByClientId(any());
    }

    @Test
    void rejectsAWrongClientSecret() {
        when(oauthClientRepository.findByClientId(ClientId.of("acme-test-app")))
                .thenReturn(Optional.of(confidentialClient));
        when(clientSecretHasher.matches(CLIENT_SECRET, confidentialClient.clientSecretHash())).thenReturn(false);

        assertThatThrownBy(() -> useCase.execute(command("a-token")))
                .isInstanceOf(OAuthIntrospectionException.class);
    }

    @Test
    void rejectsADisabledClient() {
        confidentialClient.disable();
        when(oauthClientRepository.findByClientId(ClientId.of("acme-test-app")))
                .thenReturn(Optional.of(confidentialClient));
        when(clientSecretHasher.matches(CLIENT_SECRET, confidentialClient.clientSecretHash())).thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(command("a-token")))
                .isInstanceOf(OAuthIntrospectionException.class);
    }

    @Test
    void rejectsAPublicClientEvenIfASecretIsSomehowPresented() {
        OAuthClient publicClient = OAuthClient.register(
                TENANT_ID,
                ClientId.of("tv-app-public"),
                null,
                "Smart TV App",
                Set.of(),
                Set.of("openid"),
                Set.of(GrantType.DEVICE_CODE));
        when(oauthClientRepository.findByClientId(ClientId.of("tv-app-public"))).thenReturn(Optional.of(publicClient));
        IntrospectTokenCommand command =
                new IntrospectTokenCommand(TENANT_ID.value(), "a-token", null, "tv-app-public", "irrelevant");

        assertThatThrownBy(() -> useCase.execute(command)).isInstanceOf(OAuthIntrospectionException.class);
        verify(clientSecretHasher, never()).matches(anyString(), any());
    }
}
