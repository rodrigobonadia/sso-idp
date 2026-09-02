package com.ssoplatform.idp.application.usecase.device;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.OAuthDeviceAuthorizationException;
import com.ssoplatform.idp.application.port.out.ClientSecretHasher;
import com.ssoplatform.idp.application.port.out.DeviceCodeRepository;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.devicecode.DeviceCode;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.ClientSecretHash;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RequestDeviceAuthorizationUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final String CLIENT_ID_VALUE = "acme-cli";
    private static final String CLIENT_SECRET = "correct-client-secret";
    private static final String VERIFICATION_URI = "http://acme.localhost:8080/device";

    @Mock
    private OAuthClientRepository oauthClientRepository;

    @Mock
    private ClientSecretHasher clientSecretHasher;

    @Mock
    private DeviceCodeRepository deviceCodeRepository;

    @Mock
    private VerificationTokenHasher verificationTokenHasher;

    private RequestDeviceAuthorizationUseCase useCase;

    @BeforeEach
    void setUp() {
        useCase = new RequestDeviceAuthorizationUseCase(
                oauthClientRepository, clientSecretHasher, deviceCodeRepository, verificationTokenHasher);
    }

    private static OAuthClient confidentialClient() {
        return OAuthClient.register(
                TENANT_ID,
                ClientId.of(CLIENT_ID_VALUE),
                ClientSecretHash.of("stored-hash"),
                "Acme CLI",
                Set.of(),
                Set.of("openid", "profile"),
                Set.of(GrantType.DEVICE_CODE));
    }

    private static OAuthClient publicClient() {
        return OAuthClient.register(
                TENANT_ID,
                ClientId.of(CLIENT_ID_VALUE),
                null,
                "Acme CLI",
                Set.of(),
                Set.of("openid", "profile"),
                Set.of(GrantType.DEVICE_CODE));
    }

    private static RequestDeviceAuthorizationCommand confidentialCommand(String scope) {
        return new RequestDeviceAuthorizationCommand(
                TENANT_ID.value(), VERIFICATION_URI, null, scope, CLIENT_ID_VALUE, CLIENT_SECRET);
    }

    private static RequestDeviceAuthorizationCommand publicCommand(String scope) {
        return new RequestDeviceAuthorizationCommand(TENANT_ID.value(), VERIFICATION_URI, CLIENT_ID_VALUE, scope, null, null);
    }

    private void stubHappyPathUpTo(OAuthClient client) {
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        if (client.isConfidential()) {
            when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        }
        when(deviceCodeRepository.findByUserCode(any())).thenReturn(Optional.empty());
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("hashed-device-code"));
        when(deviceCodeRepository.save(any(DeviceCode.class))).thenAnswer(invocation -> invocation.getArgument(0));
    }

    @Test
    void issuesADeviceCodeForAConfidentialClient() {
        OAuthClient client = confidentialClient();
        stubHappyPathUpTo(client);

        RequestDeviceAuthorizationResult result = useCase.execute(confidentialCommand("openid profile"));

        assertThat(result.deviceCode()).isNotBlank();
        assertThat(result.userCode()).matches("^[A-Z0-9]{4}-[A-Z0-9]{4}$");
        assertThat(result.verificationUri()).isEqualTo(VERIFICATION_URI);
        assertThat(result.verificationUriComplete()).startsWith(VERIFICATION_URI + "?user_code=");
        assertThat(result.expiresInSeconds()).isEqualTo(RequestDeviceAuthorizationUseCase.DEVICE_CODE_VALIDITY.toSeconds());
        assertThat(result.interval()).isEqualTo(RequestDeviceAuthorizationUseCase.POLL_INTERVAL_SECONDS);
    }

    @Test
    void issuesADeviceCodeForAPublicClient() {
        OAuthClient client = publicClient();
        stubHappyPathUpTo(client);

        RequestDeviceAuthorizationResult result = useCase.execute(publicCommand("openid"));

        assertThat(result.deviceCode()).isNotBlank();
    }

    @Test
    void rejectsWhenNoCredentialsArePresent() {
        RequestDeviceAuthorizationCommand command =
                new RequestDeviceAuthorizationCommand(TENANT_ID.value(), VERIFICATION_URI, null, "openid", null, null);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthDeviceAuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuthDeviceAuthorizationException) ex).errorCode())
                        .isEqualTo("invalid_client"));
        verify(oauthClientRepository, never()).findByClientId(any());
    }

    @Test
    void rejectsAPublicClientThatPresentsBasicAuthCredentials() {
        OAuthClient client = publicClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));

        assertThatThrownBy(() -> useCase.execute(confidentialCommand("openid")))
                .isInstanceOf(OAuthDeviceAuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuthDeviceAuthorizationException) ex).errorCode())
                        .isEqualTo("invalid_client"));
    }

    @Test
    void rejectsAConfidentialClientThatOmitsBasicAuthCredentials() {
        OAuthClient client = confidentialClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));

        assertThatThrownBy(() -> useCase.execute(publicCommand("openid")))
                .isInstanceOf(OAuthDeviceAuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuthDeviceAuthorizationException) ex).errorCode())
                        .isEqualTo("invalid_client"));
    }

    @Test
    void rejectsEmptyScope() {
        OAuthClient client = confidentialClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(confidentialCommand(null)))
                .isInstanceOf(OAuthDeviceAuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuthDeviceAuthorizationException) ex).errorCode())
                        .isEqualTo("invalid_request"));
    }

    @Test
    void rejectsAScopeTheClientIsNotAllowed() {
        OAuthClient client = confidentialClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(confidentialCommand("email")))
                .isInstanceOf(OAuthDeviceAuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuthDeviceAuthorizationException) ex).errorCode())
                        .isEqualTo("invalid_scope"));
    }

    @Test
    void rejectsAClientNotAuthorizedForTheDeviceCodeGrant() {
        OAuthClient client = OAuthClient.register(
                TENANT_ID,
                ClientId.of(CLIENT_ID_VALUE),
                ClientSecretHash.of("stored-hash"),
                "Acme Web App",
                Set.of(com.ssoplatform.idp.domain.oauth.RedirectUri.of("https://app.example.com/callback")),
                Set.of("openid"),
                Set.of(GrantType.AUTHORIZATION_CODE));
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(confidentialCommand("openid")))
                .isInstanceOf(OAuthDeviceAuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuthDeviceAuthorizationException) ex).errorCode())
                        .isEqualTo("unauthorized_client"));
    }

    @Test
    void rejectsADisabledClient() {
        OAuthClient client = confidentialClient();
        client.disable();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(confidentialCommand("openid")))
                .isInstanceOf(OAuthDeviceAuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuthDeviceAuthorizationException) ex).errorCode())
                        .isEqualTo("unauthorized_client"));
    }

    @Test
    void regeneratesTheUserCodeOnACollisionThenSucceeds() {
        OAuthClient client = confidentialClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        DeviceCode existing = DeviceCode.request(
                TENANT_ID,
                client.id(),
                TokenHash.of("some-other-hash"),
                com.ssoplatform.idp.domain.devicecode.UserCode.generate(),
                Set.of("openid"),
                java.time.Instant.now(),
                java.time.Duration.ofMinutes(10));
        when(deviceCodeRepository.findByUserCode(any())).thenReturn(Optional.of(existing)).thenReturn(Optional.empty());
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("hashed-device-code"));
        when(deviceCodeRepository.save(any(DeviceCode.class))).thenAnswer(invocation -> invocation.getArgument(0));

        RequestDeviceAuthorizationResult result = useCase.execute(confidentialCommand("openid"));

        assertThat(result.deviceCode()).isNotBlank();
        verify(deviceCodeRepository, org.mockito.Mockito.times(2)).findByUserCode(any());
    }

    @Test
    void throwsWhenUserCodeGenerationExhaustsAllAttempts() {
        OAuthClient client = confidentialClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        DeviceCode existing = DeviceCode.request(
                TENANT_ID,
                client.id(),
                TokenHash.of("some-other-hash"),
                com.ssoplatform.idp.domain.devicecode.UserCode.generate(),
                Set.of("openid"),
                java.time.Instant.now(),
                java.time.Duration.ofMinutes(10));
        when(deviceCodeRepository.findByUserCode(any())).thenReturn(Optional.of(existing));

        assertThatThrownBy(() -> useCase.execute(confidentialCommand("openid")))
                .isInstanceOf(IllegalStateException.class);
    }
}
