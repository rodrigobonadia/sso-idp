package com.ssoplatform.idp.application.usecase.revocation;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.OAuthRevocationException;
import com.ssoplatform.idp.application.port.out.ClientSecretHasher;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.application.port.out.RefreshTokenRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.ClientSecretHash;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.OAuthClientId;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.refreshtoken.RefreshToken;
import com.ssoplatform.idp.domain.refreshtoken.RefreshTokenFamilyId;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RevokeTokenUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final TenantId OTHER_TENANT_ID = TenantId.generate();
    private static final String CLIENT_SECRET = "s3cr3t-value";

    @Mock
    private OAuthClientRepository oauthClientRepository;

    @Mock
    private ClientSecretHasher clientSecretHasher;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private VerificationTokenHasher verificationTokenHasher;

    private RevokeTokenUseCase useCase;
    private OAuthClient confidentialClient;

    @BeforeEach
    void setUp() {
        useCase = new RevokeTokenUseCase(
                oauthClientRepository, clientSecretHasher, refreshTokenRepository, verificationTokenHasher);
        confidentialClient = OAuthClient.register(
                TENANT_ID,
                ClientId.of("acme-test-app"),
                ClientSecretHash.of("stored-hash"),
                "Acme Test App",
                Set.of(RedirectUri.of("https://app.example.com/callback")),
                Set.of("openid"),
                Set.of(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN));
    }

    private RevokeTokenCommand command(String token) {
        return new RevokeTokenCommand(TENANT_ID.value(), token, null, "acme-test-app", CLIENT_SECRET);
    }

    private void stubSuccessfulClientAuth() {
        when(oauthClientRepository.findByClientId(ClientId.of("acme-test-app")))
                .thenReturn(Optional.of(confidentialClient));
        when(clientSecretHasher.matches(CLIENT_SECRET, confidentialClient.clientSecretHash())).thenReturn(true);
    }

    private RefreshToken activeRefreshTokenFor(OAuthClientId clientId, TenantId tenantId, TokenHash hash) {
        return RefreshToken.issueFirst(
                tenantId, clientId, UserId.generate(), hash, Set.of("openid", "offline_access"), Instant.now(),
                Duration.ofDays(30));
    }

    @Test
    void revokesTheEntireFamilyWhenARefreshTokenIsPresented() {
        stubSuccessfulClientAuth();
        TokenHash hash = TokenHash.of("refresh-hash-1");
        when(verificationTokenHasher.hash(any())).thenReturn(hash);
        RefreshToken first = activeRefreshTokenFor(confidentialClient.id(), TENANT_ID, hash);
        RefreshToken second = RefreshToken.continueFamily(first, TokenHash.of("refresh-hash-2"), Instant.now());
        when(refreshTokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(first));
        when(refreshTokenRepository.findAllByFamilyId(first.familyId())).thenReturn(List.of(first, second));

        useCase.execute(command("raw-refresh-token-value"));

        assertThat(first.status().name()).isEqualTo("REVOKED");
        assertThat(second.status().name()).isEqualTo("REVOKED");
        verify(refreshTokenRepository, times(2)).save(any(RefreshToken.class));
    }

    @Test
    void silentlyDoesNothingForATokenNotShapedLikeARefreshToken() {
        stubSuccessfulClientAuth();

        useCase.execute(command("header.payload.signature"));

        verify(refreshTokenRepository, never()).findByTokenHash(any());
        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void silentlyDoesNothingForAnUnknownRefreshToken() {
        stubSuccessfulClientAuth();
        TokenHash hash = TokenHash.of("refresh-hash-1");
        when(verificationTokenHasher.hash(any())).thenReturn(hash);
        when(refreshTokenRepository.findByTokenHash(hash)).thenReturn(Optional.empty());

        useCase.execute(command("raw-refresh-token-value"));

        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void silentlyDoesNothingForARefreshTokenBelongingToAnotherClient() {
        stubSuccessfulClientAuth();
        TokenHash hash = TokenHash.of("refresh-hash-1");
        when(verificationTokenHasher.hash(any())).thenReturn(hash);
        RefreshToken foreign = activeRefreshTokenFor(OAuthClientId.generate(), TENANT_ID, hash);
        when(refreshTokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(foreign));

        useCase.execute(command("raw-refresh-token-value"));

        assertThat(foreign.status().name()).isEqualTo("ACTIVE");
        verify(refreshTokenRepository, never()).save(any());
        verify(refreshTokenRepository, never()).findAllByFamilyId(any(RefreshTokenFamilyId.class));
    }

    @Test
    void silentlyDoesNothingForARefreshTokenBelongingToAnotherTenant() {
        stubSuccessfulClientAuth();
        TokenHash hash = TokenHash.of("refresh-hash-1");
        when(verificationTokenHasher.hash(any())).thenReturn(hash);
        RefreshToken foreign = activeRefreshTokenFor(confidentialClient.id(), OTHER_TENANT_ID, hash);
        when(refreshTokenRepository.findByTokenHash(hash)).thenReturn(Optional.of(foreign));

        useCase.execute(command("raw-refresh-token-value"));

        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void rejectsABlankToken() {
        stubSuccessfulClientAuth();

        assertThatThrownBy(() -> useCase.execute(command("  ")))
                .isInstanceOf(OAuthRevocationException.class)
                .satisfies(ex -> assertThat(((OAuthRevocationException) ex).errorCode()).isEqualTo("invalid_request"));
    }

    @Test
    void rejectsMissingClientCredentials() {
        RevokeTokenCommand command = new RevokeTokenCommand(TENANT_ID.value(), "a-token", null, null, null);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthRevocationException.class)
                .satisfies(ex -> assertThat(((OAuthRevocationException) ex).errorCode()).isEqualTo("invalid_client"));
        verify(oauthClientRepository, never()).findByClientId(any());
    }

    @Test
    void rejectsAWrongClientSecret() {
        when(oauthClientRepository.findByClientId(ClientId.of("acme-test-app")))
                .thenReturn(Optional.of(confidentialClient));
        when(clientSecretHasher.matches(CLIENT_SECRET, confidentialClient.clientSecretHash())).thenReturn(false);

        assertThatThrownBy(() -> useCase.execute(command("a-token"))).isInstanceOf(OAuthRevocationException.class);
    }

    @Test
    void rejectsADisabledClient() {
        confidentialClient.disable();
        when(oauthClientRepository.findByClientId(ClientId.of("acme-test-app")))
                .thenReturn(Optional.of(confidentialClient));
        when(clientSecretHasher.matches(CLIENT_SECRET, confidentialClient.clientSecretHash())).thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(command("a-token"))).isInstanceOf(OAuthRevocationException.class);
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
        RevokeTokenCommand command =
                new RevokeTokenCommand(TENANT_ID.value(), "a-token", null, "tv-app-public", "irrelevant");

        assertThatThrownBy(() -> useCase.execute(command)).isInstanceOf(OAuthRevocationException.class);
        verify(clientSecretHasher, never()).matches(anyString(), any());
    }
}
