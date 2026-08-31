package com.ssoplatform.idp.application.usecase.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.OAuthTokenException;
import com.ssoplatform.idp.application.port.out.AuthorizationCodeRepository;
import com.ssoplatform.idp.application.port.out.ClientSecretHasher;
import com.ssoplatform.idp.application.port.out.CodeVerifierValidator;
import com.ssoplatform.idp.application.port.out.JwtSigner;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.application.port.out.PrivateKeyEncryptor;
import com.ssoplatform.idp.application.port.out.RefreshTokenRepository;
import com.ssoplatform.idp.application.port.out.SigningKeyRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.authorization.AuthorizationCode;
import com.ssoplatform.idp.domain.authorization.CodeChallenge;
import com.ssoplatform.idp.domain.oauth.ClientId;
import com.ssoplatform.idp.domain.oauth.ClientSecretHash;
import com.ssoplatform.idp.domain.oauth.GrantType;
import com.ssoplatform.idp.domain.oauth.OAuthClient;
import com.ssoplatform.idp.domain.oauth.RedirectUri;
import com.ssoplatform.idp.domain.refreshtoken.RefreshToken;
import com.ssoplatform.idp.domain.signingkey.EncryptedPrivateKeyMaterial;
import com.ssoplatform.idp.domain.signingkey.KeyId;
import com.ssoplatform.idp.domain.signingkey.PublicKeyMaterial;
import com.ssoplatform.idp.domain.signingkey.SigningKey;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.UserId;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class TokenUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final TenantId OTHER_TENANT_ID = TenantId.generate();
    private static final UserId USER_ID = UserId.generate();
    private static final String CLIENT_ID_VALUE = "acme-test-app";
    private static final String CLIENT_SECRET = "correct-client-secret";
    private static final String REDIRECT_URI_VALUE = "https://app.example.com/callback";
    private static final String CODE_VALUE = "aVeryLongRawAuthorizationCodeValue12345";
    private static final String CODE_VERIFIER = "aVeryLongCodeVerifierValue1234567890abcdef";
    private static final String REFRESH_TOKEN_VALUE = "aVeryLongRawRefreshTokenValue1234567890";
    private static final String ISSUER = "http://acme.localhost:8080";
    private static final String SIGNED_JWT = "header.payload.signature";

    @Mock
    private OAuthClientRepository oauthClientRepository;

    @Mock
    private ClientSecretHasher clientSecretHasher;

    @Mock
    private AuthorizationCodeRepository authorizationCodeRepository;

    @Mock
    private RefreshTokenRepository refreshTokenRepository;

    @Mock
    private VerificationTokenHasher verificationTokenHasher;

    @Mock
    private CodeVerifierValidator codeVerifierValidator;

    @Mock
    private SigningKeyRepository signingKeyRepository;

    @Mock
    private PrivateKeyEncryptor privateKeyEncryptor;

    @Mock
    private JwtSigner jwtSigner;

    private TokenUseCase useCase;

    @BeforeEach
    void setUp() {
        useCase = new TokenUseCase(
                oauthClientRepository,
                clientSecretHasher,
                authorizationCodeRepository,
                refreshTokenRepository,
                verificationTokenHasher,
                codeVerifierValidator,
                signingKeyRepository,
                privateKeyEncryptor,
                jwtSigner);
    }

    private static OAuthClient activeClient() {
        return OAuthClient.register(
                TENANT_ID,
                ClientId.of(CLIENT_ID_VALUE),
                ClientSecretHash.of("stored-hash"),
                "Acme Test App",
                Set.of(RedirectUri.of(REDIRECT_URI_VALUE)),
                Set.of("openid", "profile"),
                Set.of(GrantType.AUTHORIZATION_CODE));
    }

    private static OAuthClient activeClientWithOfflineAccessAndRefresh() {
        return OAuthClient.register(
                TENANT_ID,
                ClientId.of(CLIENT_ID_VALUE),
                ClientSecretHash.of("stored-hash"),
                "Acme Test App",
                Set.of(RedirectUri.of(REDIRECT_URI_VALUE)),
                Set.of("openid", "profile", "offline_access"),
                Set.of(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN));
    }

    private static AuthorizationCode codeFor(OAuthClient client, Set<String> scopes, String nonce) {
        return AuthorizationCode.issue(
                TENANT_ID,
                client.id(),
                USER_ID,
                TokenHash.of("hashed-code"),
                RedirectUri.of(REDIRECT_URI_VALUE),
                scopes,
                CodeChallenge.of("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
                nonce,
                Instant.now(),
                Duration.ofMinutes(5));
    }

    private static SigningKey currentSigningKey() {
        return SigningKey.generate(
                TENANT_ID,
                KeyId.generate(),
                PublicKeyMaterial.of("cHVibGljLWtleS1kZXI="),
                EncryptedPrivateKeyMaterial.of("ZW5jcnlwdGVkLXByaXZhdGUta2V5"));
    }

    private static RefreshToken refreshTokenFor(OAuthClient client, Set<String> scopes) {
        return RefreshToken.issueFirst(
                TENANT_ID, client.id(), USER_ID, TokenHash.of("hashed-refresh-token"), scopes, Instant.now(),
                TokenUseCase.REFRESH_TOKEN_FAMILY_VALIDITY);
    }

    private static TokenCommand validCommand() {
        return new TokenCommand(
                TENANT_ID.value(), ISSUER, "authorization_code", CODE_VALUE, REDIRECT_URI_VALUE, CODE_VERIFIER, null,
                CLIENT_ID_VALUE, CLIENT_SECRET);
    }

    private static TokenCommand validRefreshCommand() {
        return new TokenCommand(
                TENANT_ID.value(), ISSUER, "refresh_token", null, null, null, REFRESH_TOKEN_VALUE, CLIENT_ID_VALUE,
                CLIENT_SECRET);
    }

    /** Wires the mocks so a fully valid authorization_code request succeeds, for tests that only vary one thing. */
    private void stubHappyPathUpTo(OAuthClient client, AuthorizationCode code) {
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("hashed-code"));
        when(authorizationCodeRepository.findByCodeHash(TokenHash.of("hashed-code"))).thenReturn(Optional.of(code));
        when(codeVerifierValidator.matches(eq(CODE_VERIFIER), any(CodeChallenge.class))).thenReturn(true);
        when(authorizationCodeRepository.save(any(AuthorizationCode.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(signingKeyRepository.findCurrentByTenantId(TENANT_ID)).thenReturn(Optional.of(currentSigningKey()));
        when(privateKeyEncryptor.decrypt(any(EncryptedPrivateKeyMaterial.class))).thenReturn(new byte[] {1, 2, 3});
        when(jwtSigner.sign(any(), any(), anyString())).thenReturn(SIGNED_JWT);
    }

    /** Wires the mocks so a fully valid refresh_token request succeeds, for tests that only vary one thing. */
    private void stubRefreshHappyPathUpTo(OAuthClient client, RefreshToken refreshToken) {
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        when(verificationTokenHasher.hash(any(RawVerificationToken.class)))
                .thenReturn(TokenHash.of("hashed-refresh-token"));
        when(refreshTokenRepository.findByTokenHash(TokenHash.of("hashed-refresh-token")))
                .thenReturn(Optional.of(refreshToken));
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));
        when(signingKeyRepository.findCurrentByTenantId(TENANT_ID)).thenReturn(Optional.of(currentSigningKey()));
        when(privateKeyEncryptor.decrypt(any(EncryptedPrivateKeyMaterial.class))).thenReturn(new byte[] {1, 2, 3});
        when(jwtSigner.sign(any(), any(), anyString())).thenReturn(SIGNED_JWT);
    }

    @Test
    void issuesAnAccessTokenAndNoIdTokenWhenOpenidWasNotGranted() {
        OAuthClient client = activeClient();
        AuthorizationCode code = codeFor(client, Set.of("profile"), null);
        stubHappyPathUpTo(client, code);

        TokenResult result = useCase.execute(validCommand());

        assertThat(result.accessToken()).isEqualTo(SIGNED_JWT);
        assertThat(result.expiresInSeconds()).isEqualTo(TokenUseCase.ACCESS_TOKEN_VALIDITY.toSeconds());
        assertThat(result.idToken()).isNull();
        verify(jwtSigner, org.mockito.Mockito.times(1)).sign(any(), any(), anyString());
    }

    @Test
    void issuesAnIdTokenWhenOpenidScopeWasGranted() {
        OAuthClient client = activeClient();
        AuthorizationCode code = codeFor(client, Set.of("openid", "profile"), null);
        stubHappyPathUpTo(client, code);

        TokenResult result = useCase.execute(validCommand());

        assertThat(result.idToken()).isEqualTo(SIGNED_JWT);
        verify(jwtSigner, org.mockito.Mockito.times(2)).sign(any(), any(), anyString());
    }

    @Test
    void includesTheNonceClaimOnTheIdTokenWhenTheCodeHadOne() {
        OAuthClient client = activeClient();
        AuthorizationCode code = codeFor(client, Set.of("openid"), "abc-nonce");
        stubHappyPathUpTo(client, code);

        useCase.execute(validCommand());

        ArgumentCaptor<Map<String, Object>> claimsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(jwtSigner, org.mockito.Mockito.times(2)).sign(claimsCaptor.capture(), any(), anyString());
        boolean anyClaimsCarryNonce =
                claimsCaptor.getAllValues().stream().anyMatch(claims -> "abc-nonce".equals(claims.get("nonce")));
        assertThat(anyClaimsCarryNonce).isTrue();
    }

    @Test
    void omitsTheNonceClaimWhenTheCodeHadNone() {
        OAuthClient client = activeClient();
        AuthorizationCode code = codeFor(client, Set.of("openid"), null);
        stubHappyPathUpTo(client, code);

        useCase.execute(validCommand());

        ArgumentCaptor<Map<String, Object>> claimsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(jwtSigner, org.mockito.Mockito.times(2)).sign(claimsCaptor.capture(), any(), anyString());
        boolean anyClaimsCarryNonce = claimsCaptor.getAllValues().stream().anyMatch(claims -> claims.containsKey("nonce"));
        assertThat(anyClaimsCarryNonce).isFalse();
    }

    @Test
    void theAccessTokenClaimsCarryTheGrantedScopesAndClientId() {
        OAuthClient client = activeClient();
        AuthorizationCode code = codeFor(client, Set.of("openid", "profile"), null);
        stubHappyPathUpTo(client, code);

        useCase.execute(validCommand());

        ArgumentCaptor<Map<String, Object>> claimsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(jwtSigner, org.mockito.Mockito.times(2)).sign(claimsCaptor.capture(), any(), anyString());
        Map<String, Object> accessTokenClaims = claimsCaptor.getAllValues().get(0);
        assertThat(accessTokenClaims.get("iss")).isEqualTo(ISSUER);
        assertThat(accessTokenClaims.get("sub")).isEqualTo(USER_ID.value().toString());
        assertThat(accessTokenClaims.get("aud")).isEqualTo(CLIENT_ID_VALUE);
        assertThat(accessTokenClaims.get("client_id")).isEqualTo(CLIENT_ID_VALUE);
        assertThat(accessTokenClaims.get("scope")).isIn("openid profile", "profile openid");
    }

    @Test
    void marksTheCodeConsumedOnSuccess() {
        OAuthClient client = activeClient();
        AuthorizationCode code = codeFor(client, Set.of("profile"), null);
        stubHappyPathUpTo(client, code);

        useCase.execute(validCommand());

        assertThat(code.isConsumed()).isTrue();
        verify(authorizationCodeRepository).save(code);
    }

    @Test
    void doesNotIssueARefreshTokenWhenOfflineAccessWasNotGranted() {
        OAuthClient client = activeClientWithOfflineAccessAndRefresh();
        AuthorizationCode code = codeFor(client, Set.of("openid", "profile"), null);
        stubHappyPathUpTo(client, code);

        TokenResult result = useCase.execute(validCommand());

        assertThat(result.refreshToken()).isNull();
        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void doesNotIssueARefreshTokenWhenTheClientDoesNotSupportTheRefreshTokenGrant() {
        OAuthClient client = activeClient();
        AuthorizationCode code = codeFor(client, Set.of("openid", "offline_access"), null);
        stubHappyPathUpTo(client, code);

        TokenResult result = useCase.execute(validCommand());

        assertThat(result.refreshToken()).isNull();
        verify(refreshTokenRepository, never()).save(any());
    }

    @Test
    void issuesAFirstRefreshTokenWhenOfflineAccessWasGrantedAndTheClientSupportsTheRefreshTokenGrant() {
        OAuthClient client = activeClientWithOfflineAccessAndRefresh();
        AuthorizationCode code = codeFor(client, Set.of("openid", "offline_access"), null);
        stubHappyPathUpTo(client, code);
        when(refreshTokenRepository.save(any(RefreshToken.class))).thenAnswer(invocation -> invocation.getArgument(0));

        TokenResult result = useCase.execute(validCommand());

        assertThat(result.refreshToken()).isNotBlank();
        verify(refreshTokenRepository).save(any(RefreshToken.class));
    }

    @Test
    void rejectsAnUnsupportedGrantType() {
        TokenCommand command = new TokenCommand(
                TENANT_ID.value(), ISSUER, "client_credentials", CODE_VALUE, REDIRECT_URI_VALUE, CODE_VERIFIER, null,
                CLIENT_ID_VALUE, CLIENT_SECRET);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("unsupported_grant_type"));
        verify(oauthClientRepository, never()).findByClientId(any());
    }

    @Test
    void rejectsWhenNoBasicAuthCredentialsArePresent() {
        TokenCommand command = new TokenCommand(
                TENANT_ID.value(), ISSUER, "authorization_code", CODE_VALUE, REDIRECT_URI_VALUE, CODE_VERIFIER, null,
                null, null);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_client"));
        verify(oauthClientRepository, never()).findByClientId(any());
    }

    @Test
    void rejectsAMalformedBasicAuthClientId() {
        TokenCommand command = new TokenCommand(
                TENANT_ID.value(), ISSUER, "authorization_code", CODE_VALUE, REDIRECT_URI_VALUE, CODE_VERIFIER, null,
                "!!", CLIENT_SECRET);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_client"));
    }

    @Test
    void rejectsAnUnknownClientId() {
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(validCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_client"));
    }

    @Test
    void rejectsAClientThatBelongsToADifferentTenant() {
        OAuthClient clientOfOtherTenant = OAuthClient.register(
                OTHER_TENANT_ID,
                ClientId.of(CLIENT_ID_VALUE),
                ClientSecretHash.of("stored-hash"),
                "Someone Else's App",
                Set.of(RedirectUri.of(REDIRECT_URI_VALUE)),
                Set.of("openid"),
                Set.of(GrantType.AUTHORIZATION_CODE));
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE)))
                .thenReturn(Optional.of(clientOfOtherTenant));

        assertThatThrownBy(() -> useCase.execute(validCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_client"));
    }

    @Test
    void rejectsAWrongClientSecret() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(false);

        assertThatThrownBy(() -> useCase.execute(validCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_client"));
    }

    @Test
    void rejectsADisabledClientWithUnauthorizedClientError() {
        OAuthClient client = activeClient();
        client.disable();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(validCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("unauthorized_client"));
    }

    @Test
    void rejectsAClientNotAuthorizedForTheAuthorizationCodeGrant() {
        OAuthClient client = OAuthClient.register(
                TENANT_ID,
                ClientId.of(CLIENT_ID_VALUE),
                ClientSecretHash.of("stored-hash"),
                "Acme Test App",
                Set.of(RedirectUri.of(REDIRECT_URI_VALUE)),
                Set.of("openid"),
                Set.of(GrantType.CLIENT_CREDENTIALS));
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(validCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("unauthorized_client"));
    }

    @Test
    void rejectsABlankCode() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);

        TokenCommand command = new TokenCommand(
                TENANT_ID.value(), ISSUER, "authorization_code", "  ", REDIRECT_URI_VALUE, CODE_VERIFIER, null,
                CLIENT_ID_VALUE, CLIENT_SECRET);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_request"));
    }

    @Test
    void rejectsABlankRedirectUri() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);

        TokenCommand command = new TokenCommand(
                TENANT_ID.value(), ISSUER, "authorization_code", CODE_VALUE, "  ", CODE_VERIFIER, null,
                CLIENT_ID_VALUE, CLIENT_SECRET);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_request"));
    }

    @Test
    void rejectsABlankCodeVerifier() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);

        TokenCommand command = new TokenCommand(
                TENANT_ID.value(), ISSUER, "authorization_code", CODE_VALUE, REDIRECT_URI_VALUE, "  ", null,
                CLIENT_ID_VALUE, CLIENT_SECRET);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_request"));
    }

    @Test
    void rejectsAMalformedCodeAsInvalidGrant() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);

        TokenCommand command = new TokenCommand(
                TENANT_ID.value(), ISSUER, "authorization_code", "!", REDIRECT_URI_VALUE, CODE_VERIFIER, null,
                CLIENT_ID_VALUE, CLIENT_SECRET);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_grant"));
    }

    @Test
    void rejectsAnUnknownCode() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("hashed-code"));
        when(authorizationCodeRepository.findByCodeHash(TokenHash.of("hashed-code"))).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(validCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_grant"));
    }

    @Test
    void rejectsACodeIssuedToADifferentClient() {
        OAuthClient client = activeClient();
        OAuthClient otherClient = OAuthClient.register(
                TENANT_ID,
                ClientId.of("some-other-app"),
                ClientSecretHash.of("stored-hash"),
                "Other App",
                Set.of(RedirectUri.of(REDIRECT_URI_VALUE)),
                Set.of("openid"),
                Set.of(GrantType.AUTHORIZATION_CODE));
        AuthorizationCode codeForOtherClient = codeFor(otherClient, Set.of("openid"), null);

        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("hashed-code"));
        when(authorizationCodeRepository.findByCodeHash(TokenHash.of("hashed-code")))
                .thenReturn(Optional.of(codeForOtherClient));

        assertThatThrownBy(() -> useCase.execute(validCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_grant"));
    }

    @Test
    void rejectsAMismatchedRedirectUri() {
        OAuthClient client = activeClient();
        AuthorizationCode code = AuthorizationCode.issue(
                TENANT_ID,
                client.id(),
                USER_ID,
                TokenHash.of("hashed-code"),
                RedirectUri.of("https://different.example.com/callback"),
                Set.of("openid"),
                CodeChallenge.of("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
                null,
                Instant.now(),
                Duration.ofMinutes(5));

        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("hashed-code"));
        when(authorizationCodeRepository.findByCodeHash(TokenHash.of("hashed-code"))).thenReturn(Optional.of(code));

        assertThatThrownBy(() -> useCase.execute(validCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_grant"));
    }

    @Test
    void rejectsAMalformedRedirectUriAsInvalidGrant() {
        OAuthClient client = activeClient();
        AuthorizationCode code = codeFor(client, Set.of("openid"), null);
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("hashed-code"));
        when(authorizationCodeRepository.findByCodeHash(TokenHash.of("hashed-code"))).thenReturn(Optional.of(code));

        TokenCommand command = new TokenCommand(
                TENANT_ID.value(), ISSUER, "authorization_code", CODE_VALUE, "not a uri", CODE_VERIFIER, null,
                CLIENT_ID_VALUE, CLIENT_SECRET);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_grant"));
    }

    @Test
    void rejectsWhenTheCodeVerifierDoesNotMatchTheChallenge() {
        OAuthClient client = activeClient();
        AuthorizationCode code = codeFor(client, Set.of("openid"), null);
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("hashed-code"));
        when(authorizationCodeRepository.findByCodeHash(TokenHash.of("hashed-code"))).thenReturn(Optional.of(code));
        when(codeVerifierValidator.matches(eq(CODE_VERIFIER), any(CodeChallenge.class))).thenReturn(false);

        assertThatThrownBy(() -> useCase.execute(validCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_grant"));
        verify(authorizationCodeRepository, never()).save(any());
        assertThat(code.isConsumed()).isFalse();
    }

    @Test
    void rejectsAnAlreadyConsumedCode() {
        OAuthClient client = activeClient();
        AuthorizationCode code = codeFor(client, Set.of("openid"), null);
        code.consume(Instant.now());
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("hashed-code"));
        when(authorizationCodeRepository.findByCodeHash(TokenHash.of("hashed-code"))).thenReturn(Optional.of(code));
        when(codeVerifierValidator.matches(eq(CODE_VERIFIER), any(CodeChallenge.class))).thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(validCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_grant"));
    }

    @Test
    void rejectsAnExpiredCode() {
        OAuthClient client = activeClient();
        AuthorizationCode code = AuthorizationCode.issue(
                TENANT_ID,
                client.id(),
                USER_ID,
                TokenHash.of("hashed-code"),
                RedirectUri.of(REDIRECT_URI_VALUE),
                Set.of("openid"),
                CodeChallenge.of("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"),
                null,
                Instant.now().minus(Duration.ofMinutes(10)),
                Duration.ofMinutes(5));
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("hashed-code"));
        when(authorizationCodeRepository.findByCodeHash(TokenHash.of("hashed-code"))).thenReturn(Optional.of(code));
        when(codeVerifierValidator.matches(eq(CODE_VERIFIER), any(CodeChallenge.class))).thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(validCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_grant"));
    }

    @Test
    void throwsAnIllegalStateExceptionWhenTheTenantHasNoCurrentSigningKey() {
        OAuthClient client = activeClient();
        AuthorizationCode code = codeFor(client, Set.of("openid"), null);
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("hashed-code"));
        when(authorizationCodeRepository.findByCodeHash(TokenHash.of("hashed-code"))).thenReturn(Optional.of(code));
        when(codeVerifierValidator.matches(eq(CODE_VERIFIER), any(CodeChallenge.class))).thenReturn(true);
        when(authorizationCodeRepository.save(any(AuthorizationCode.class)))
                .thenAnswer(invocation -> invocation.getArgument(0));
        when(signingKeyRepository.findCurrentByTenantId(TENANT_ID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(validCommand())).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void rotatesARefreshTokenAndIssuesANewAccessTokenPlusANewRefreshToken() {
        OAuthClient client = activeClientWithOfflineAccessAndRefresh();
        RefreshToken refreshToken = refreshTokenFor(client, Set.of("openid", "offline_access"));
        stubRefreshHappyPathUpTo(client, refreshToken);

        TokenResult result = useCase.execute(validRefreshCommand());

        assertThat(result.accessToken()).isEqualTo(SIGNED_JWT);
        assertThat(result.idToken()).isEqualTo(SIGNED_JWT);
        assertThat(result.refreshToken()).isNotBlank();
        assertThat(refreshToken.status().name()).isEqualTo("ROTATED");
        verify(refreshTokenRepository, org.mockito.Mockito.times(2)).save(any(RefreshToken.class));
    }

    @Test
    void doesNotCarryANonceOnTheIdTokenIssuedByARefresh() {
        OAuthClient client = activeClientWithOfflineAccessAndRefresh();
        RefreshToken refreshToken = refreshTokenFor(client, Set.of("openid", "offline_access"));
        stubRefreshHappyPathUpTo(client, refreshToken);

        useCase.execute(validRefreshCommand());

        ArgumentCaptor<Map<String, Object>> claimsCaptor = ArgumentCaptor.forClass(Map.class);
        verify(jwtSigner, org.mockito.Mockito.times(2)).sign(claimsCaptor.capture(), any(), anyString());
        boolean anyClaimsCarryNonce = claimsCaptor.getAllValues().stream().anyMatch(claims -> claims.containsKey("nonce"));
        assertThat(anyClaimsCarryNonce).isFalse();
    }

    @Test
    void rejectsARefreshTokenGrantWhenTheClientIsNotAuthorizedForIt() {
        OAuthClient client = activeClient();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(validRefreshCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("unauthorized_client"));
    }

    @Test
    void rejectsABlankRefreshToken() {
        OAuthClient client = activeClientWithOfflineAccessAndRefresh();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);

        TokenCommand command = new TokenCommand(
                TENANT_ID.value(), ISSUER, "refresh_token", null, null, null, "  ", CLIENT_ID_VALUE, CLIENT_SECRET);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_request"));
    }

    @Test
    void rejectsAMalformedRefreshTokenAsInvalidGrant() {
        OAuthClient client = activeClientWithOfflineAccessAndRefresh();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);

        TokenCommand command = new TokenCommand(
                TENANT_ID.value(), ISSUER, "refresh_token", null, null, null, "!", CLIENT_ID_VALUE, CLIENT_SECRET);

        assertThatThrownBy(() -> useCase.execute(command))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_grant"));
    }

    @Test
    void rejectsAnUnknownRefreshToken() {
        OAuthClient client = activeClientWithOfflineAccessAndRefresh();
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        when(verificationTokenHasher.hash(any(RawVerificationToken.class)))
                .thenReturn(TokenHash.of("hashed-refresh-token"));
        when(refreshTokenRepository.findByTokenHash(TokenHash.of("hashed-refresh-token"))).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(validRefreshCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_grant"));
    }

    @Test
    void rejectsARefreshTokenIssuedToADifferentClient() {
        OAuthClient client = activeClientWithOfflineAccessAndRefresh();
        OAuthClient otherClient = OAuthClient.register(
                TENANT_ID,
                ClientId.of("some-other-app"),
                ClientSecretHash.of("stored-hash"),
                "Other App",
                Set.of(RedirectUri.of(REDIRECT_URI_VALUE)),
                Set.of("openid", "offline_access"),
                Set.of(GrantType.AUTHORIZATION_CODE, GrantType.REFRESH_TOKEN));
        RefreshToken refreshTokenForOtherClient = refreshTokenFor(otherClient, Set.of("openid", "offline_access"));

        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        when(verificationTokenHasher.hash(any(RawVerificationToken.class)))
                .thenReturn(TokenHash.of("hashed-refresh-token"));
        when(refreshTokenRepository.findByTokenHash(TokenHash.of("hashed-refresh-token")))
                .thenReturn(Optional.of(refreshTokenForOtherClient));

        assertThatThrownBy(() -> useCase.execute(validRefreshCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_grant"));
    }

    @Test
    void rejectsAnExpiredRefreshTokenFamily() {
        OAuthClient client = activeClientWithOfflineAccessAndRefresh();
        RefreshToken refreshToken = RefreshToken.issueFirst(
                TENANT_ID,
                client.id(),
                USER_ID,
                TokenHash.of("hashed-refresh-token"),
                Set.of("openid", "offline_access"),
                Instant.now().minus(Duration.ofDays(31)),
                TokenUseCase.REFRESH_TOKEN_FAMILY_VALIDITY);
        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        when(verificationTokenHasher.hash(any(RawVerificationToken.class)))
                .thenReturn(TokenHash.of("hashed-refresh-token"));
        when(refreshTokenRepository.findByTokenHash(TokenHash.of("hashed-refresh-token")))
                .thenReturn(Optional.of(refreshToken));

        assertThatThrownBy(() -> useCase.execute(validRefreshCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_grant"));
        verify(refreshTokenRepository, never()).findAllByFamilyId(any());
    }

    @Test
    void revokesTheEntireFamilyWhenAnAlreadyRotatedRefreshTokenIsPresentedAgain() {
        OAuthClient client = activeClientWithOfflineAccessAndRefresh();
        RefreshToken refreshToken = refreshTokenFor(client, Set.of("openid", "offline_access"));
        refreshToken.rotate(Instant.now());
        RefreshToken sibling = RefreshToken.continueFamily(refreshToken, TokenHash.of("hashed-sibling"), Instant.now());

        when(oauthClientRepository.findByClientId(ClientId.of(CLIENT_ID_VALUE))).thenReturn(Optional.of(client));
        when(clientSecretHasher.matches(eq(CLIENT_SECRET), any(ClientSecretHash.class))).thenReturn(true);
        when(verificationTokenHasher.hash(any(RawVerificationToken.class)))
                .thenReturn(TokenHash.of("hashed-refresh-token"));
        when(refreshTokenRepository.findByTokenHash(TokenHash.of("hashed-refresh-token")))
                .thenReturn(Optional.of(refreshToken));
        when(refreshTokenRepository.findAllByFamilyId(refreshToken.familyId()))
                .thenReturn(List.of(refreshToken, sibling));

        assertThatThrownBy(() -> useCase.execute(validRefreshCommand()))
                .isInstanceOf(OAuthTokenException.class)
                .satisfies(ex -> assertThat(((OAuthTokenException) ex).errorCode()).isEqualTo("invalid_grant"));

        assertThat(refreshToken.status().name()).isEqualTo("REVOKED");
        assertThat(sibling.status().name()).isEqualTo("REVOKED");
        verify(refreshTokenRepository).save(refreshToken);
        verify(refreshTokenRepository).save(sibling);
    }
}
