package com.ssoplatform.idp.application.usecase.authorization;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.OAuthAuthorizationException;
import com.ssoplatform.idp.application.exception.OAuthClientNotFoundException;
import com.ssoplatform.idp.application.exception.RedirectUriNotRegisteredException;
import com.ssoplatform.idp.application.port.out.AuthorizationCodeRepository;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.authorization.AuthorizationCode;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.ClientSecretHash;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.InvalidClientIdException;
import com.ssoplatform.idp.domain.oauth.InvalidRedirectUriException;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
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
class AuthorizeUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final TenantId OTHER_TENANT_ID = TenantId.generate();
    private static final UserId USER_ID = UserId.generate();
    private static final String CLIENT_ID_VALUE = "acme-test-app";
    private static final String REDIRECT_URI_VALUE = "https://app.example.com/callback";
    private static final String CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    @Mock
    private OAuthClientRepository oauthClientRepository;

    @Mock
    private AuthorizationCodeRepository authorizationCodeRepository;

    @Mock
    private VerificationTokenHasher verificationTokenHasher;

    private AuthorizeUseCase useCase;

    @BeforeEach
    void setUp() {
        useCase = new AuthorizeUseCase(oauthClientRepository, authorizationCodeRepository, verificationTokenHasher);
    }

    private static OAuthClient activeClient() {
        return OAuthClient.register(
                TENANT_ID,
                ClientId.of(CLIENT_ID_VALUE),
                ClientSecretHash.of("some-hash"),
                "Acme Test App",
                Set.of(RedirectUri.of(REDIRECT_URI_VALUE)),
                Set.of("openid", "profile"),
                Set.of(GrantType.AUTHORIZATION_CODE));
    }

    private static AuthorizeCommand validCommand() {
        return validCommand(null);
    }

    private static AuthorizeCommand validCommand(String nonce) {
        return new AuthorizeCommand(
                TENANT_ID.value(),
                USER_ID.value(),
                CLIENT_ID_VALUE,
                REDIRECT_URI_VALUE,
                "code",
                "openid profile",
                "xyz-state",
                CODE_CHALLENGE,
                "S256",
                nonce);
    }

    @Test
    void issuesACodeForAFullyValidRequestAndEchoesState() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("hashed-code"));
        when(authorizationCodeRepository.save(any(AuthorizationCode.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        AuthorizeResult result = useCase.execute(validCommand());

        assertThat(result.code()).isNotBlank();
        assertThat(result.redirectUri()).isEqualTo(REDIRECT_URI_VALUE);
        assertThat(result.state()).isEqualTo("xyz-state");
        verify(authorizationCodeRepository).save(any(AuthorizationCode.class));
    }

    @Test
    void allowsAnAbsentState() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("hashed-code"));
        when(authorizationCodeRepository.save(any(AuthorizationCode.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        AuthorizeCommand command = new AuthorizeCommand(
                TENANT_ID.value(),
                USER_ID.value(),
                CLIENT_ID_VALUE,
                REDIRECT_URI_VALUE,
                "code",
                "openid",
                null,
                CODE_CHALLENGE,
                "S256",
                null);

        AuthorizeResult result = useCase.execute(command);

        assertThat(result.state()).isNull();
    }

    @Test
    void threadsANonceOntoTheIssuedCodeWhenSupplied() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("hashed-code"));
        when(authorizationCodeRepository.save(any(AuthorizationCode.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        useCase.execute(validCommand("abc123-nonce"));

        var captor = org.mockito.ArgumentCaptor.forClass(AuthorizationCode.class);
        verify(authorizationCodeRepository).save(captor.capture());
        assertThat(captor.getValue().nonce()).isEqualTo("abc123-nonce");
    }

    @Test
    void issuesACodeWithANullNonceWhenNoneIsSupplied() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("hashed-code"));
        when(authorizationCodeRepository.save(any(AuthorizationCode.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));

        useCase.execute(validCommand());

        var captor = org.mockito.ArgumentCaptor.forClass(AuthorizationCode.class);
        verify(authorizationCodeRepository).save(captor.capture());
        assertThat(captor.getValue().nonce()).isNull();
    }

    @Test
    void rejectsAMalformedClientIdWithoutTouchingTheRepository() {
        AuthorizeCommand command = new AuthorizeCommand(
                TENANT_ID.value(), USER_ID.value(), "!!", REDIRECT_URI_VALUE, "code", "openid", null, CODE_CHALLENGE,
                "S256", null);

        assertThatThrownBy(() -> useCase.execute(command)).isInstanceOf(InvalidClientIdException.class);
        verify(oauthClientRepository, never()).findByClientId(any());
    }

    @Test
    void rejectsAnUnknownClientId() {
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(validCommand())).isInstanceOf(OAuthClientNotFoundException.class);
        verify(authorizationCodeRepository, never()).save(any());
    }

    @Test
    void rejectsAClientThatBelongsToADifferentTenant() {
        OAuthClient clientOfOtherTenant = OAuthClient.register(
                OTHER_TENANT_ID,
                ClientId.of(CLIENT_ID_VALUE),
                ClientSecretHash.of("some-hash"),
                "Someone Else's App",
                Set.of(RedirectUri.of(REDIRECT_URI_VALUE)),
                Set.of("openid"),
                Set.of(GrantType.AUTHORIZATION_CODE));
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE)))
                .thenReturn(Optional.of(clientOfOtherTenant));

        assertThatThrownBy(() -> useCase.execute(validCommand())).isInstanceOf(OAuthClientNotFoundException.class);
    }

    @Test
    void rejectsAMalformedRedirectUri() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));

        AuthorizeCommand command = new AuthorizeCommand(
                TENANT_ID.value(), USER_ID.value(), CLIENT_ID_VALUE, "not a uri", "code", "openid", null, CODE_CHALLENGE,
                "S256", null);

        assertThatThrownBy(() -> useCase.execute(command)).isInstanceOf(InvalidRedirectUriException.class);
    }

    @Test
    void rejectsARedirectUriThatIsNotRegisteredForTheClient() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));

        AuthorizeCommand command = new AuthorizeCommand(
                TENANT_ID.value(),
                USER_ID.value(),
                CLIENT_ID_VALUE,
                "https://evil.example.com/callback",
                "code",
                "openid",
                null,
                CODE_CHALLENGE,
                "S256",
                null);

        assertThatThrownBy(() -> useCase.execute(command)).isInstanceOf(RedirectUriNotRegisteredException.class);
    }

    @Test
    void rejectsADisabledClientWithUnauthorizedClientError() {
        OAuthClient client = activeClient();
        client.disable();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));

        assertThatThrownBy(() -> useCase.execute(validCommand()))
                .isInstanceOf(OAuthAuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuthAuthorizationException) ex).errorCode())
                        .isEqualTo("unauthorized_client"));
    }

    @Test
    void rejectsAnUnsupportedResponseType() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));

        AuthorizeCommand command = new AuthorizeCommand(
                TENANT_ID.value(),
                USER_ID.value(),
                CLIENT_ID_VALUE,
                REDIRECT_URI_VALUE,
                "token",
                "openid",
                null,
                CODE_CHALLENGE,
                "S256",
                null);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthAuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuthAuthorizationException) ex).errorCode())
                        .isEqualTo("unsupported_response_type"));
    }

    @Test
    void rejectsAClientNotAuthorizedForTheAuthorizationCodeGrant() {
        OAuthClient client = OAuthClient.register(
                TENANT_ID,
                ClientId.of(CLIENT_ID_VALUE),
                ClientSecretHash.of("some-hash"),
                "Acme Test App",
                Set.of(RedirectUri.of(REDIRECT_URI_VALUE)),
                Set.of("openid"),
                Set.of(GrantType.CLIENT_CREDENTIALS));
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));

        assertThatThrownBy(() -> useCase.execute(validCommand()))
                .isInstanceOf(OAuthAuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuthAuthorizationException) ex).errorCode())
                        .isEqualTo("unauthorized_client"));
    }

    @Test
    void rejectsAMissingScopeAsInvalidRequest() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));

        AuthorizeCommand command = new AuthorizeCommand(
                TENANT_ID.value(), USER_ID.value(), CLIENT_ID_VALUE, REDIRECT_URI_VALUE, "code", "  ", null, CODE_CHALLENGE,
                "S256", null);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthAuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuthAuthorizationException) ex).errorCode())
                        .isEqualTo("invalid_request"));
    }

    @Test
    void rejectsAScopeTheClientIsNotAllowed() {
        OAuthClient client = activeClient(); // only allows openid, profile
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));

        AuthorizeCommand command = new AuthorizeCommand(
                TENANT_ID.value(), USER_ID.value(), CLIENT_ID_VALUE, REDIRECT_URI_VALUE, "code", "email", null, CODE_CHALLENGE,
                "S256", null);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthAuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuthAuthorizationException) ex).errorCode())
                        .isEqualTo("invalid_scope"));
    }

    @Test
    void rejectsAPlainCodeChallengeMethod() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));

        AuthorizeCommand command = new AuthorizeCommand(
                TENANT_ID.value(),
                USER_ID.value(),
                CLIENT_ID_VALUE,
                REDIRECT_URI_VALUE,
                "code",
                "openid",
                null,
                CODE_CHALLENGE,
                "plain",
                null);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthAuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuthAuthorizationException) ex).errorCode())
                        .isEqualTo("invalid_request"));
    }

    @Test
    void rejectsAMalformedCodeChallenge() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));

        AuthorizeCommand command = new AuthorizeCommand(
                TENANT_ID.value(), USER_ID.value(), CLIENT_ID_VALUE, REDIRECT_URI_VALUE, "code", "openid", null, "too-short",
                "S256", null);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthAuthorizationException.class)
                .satisfies(ex -> assertThat(((OAuthAuthorizationException) ex).errorCode())
                        .isEqualTo("invalid_request"));
    }
}
