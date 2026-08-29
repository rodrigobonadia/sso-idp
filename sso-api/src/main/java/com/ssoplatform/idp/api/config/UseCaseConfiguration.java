package com.ssoplatform.idp.api.config;

import com.ssoplatform.idp.application.port.out.AuthorizationCodeRepository;
import com.ssoplatform.idp.application.port.out.ClientSecretHasher;
import com.ssoplatform.idp.application.port.out.CodeVerifierValidator;
import com.ssoplatform.idp.application.port.out.EmailSender;
import com.ssoplatform.idp.application.port.out.JwtSigner;
import com.ssoplatform.idp.application.port.out.OAuthClientRepository;
import com.ssoplatform.idp.application.port.out.PasswordHasher;
import com.ssoplatform.idp.application.port.out.PasswordResetTokenRepository;
import com.ssoplatform.idp.application.port.out.PrivateKeyEncryptor;
import com.ssoplatform.idp.application.port.out.SigningKeyPairGenerator;
import com.ssoplatform.idp.application.port.out.SigningKeyRepository;
import com.ssoplatform.idp.application.port.out.TenantRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.application.port.out.VerificationTokenRepository;
import com.ssoplatform.idp.application.usecase.authorization.AuthorizeUseCase;
import com.ssoplatform.idp.application.usecase.signingkey.GenerateSigningKeyUseCase;
import com.ssoplatform.idp.application.usecase.signingkey.ListSigningKeysUseCase;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantUseCase;
import com.ssoplatform.idp.application.usecase.tenant.ResolveActiveTenantBySlugUseCase;
import com.ssoplatform.idp.application.usecase.token.TokenUseCase;
import com.ssoplatform.idp.application.usecase.user.ChangePasswordUseCase;
import com.ssoplatform.idp.application.usecase.user.CreateUserUseCase;
import com.ssoplatform.idp.application.usecase.user.LoginUseCase;
import com.ssoplatform.idp.application.usecase.user.RegisterUserUseCase;
import com.ssoplatform.idp.application.usecase.user.RequestPasswordResetUseCase;
import com.ssoplatform.idp.application.usecase.user.ResetPasswordUseCase;
import com.ssoplatform.idp.application.usecase.user.VerifyEmailUseCase;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Wires use cases (plain, framework-free classes in {@code sso-application}) as Spring beans.
 *
 * <p>Use cases are instantiated here - the composition root - rather than annotated with
 * {@code @Service} directly, because {@code sso-application} must not depend on Spring at all.
 * This keeps the Dependency Inversion Principle intact: the application layer defines the ports
 * it needs (constructor parameters here), and this configuration class, which lives in the
 * outermost layer, is the only place that knows both the use cases and their concrete
 * Spring-managed adapters.
 */
@Configuration
public class UseCaseConfiguration {

    @Bean
    public CreateTenantUseCase createTenantUseCase(TenantRepository tenantRepository) {
        return new CreateTenantUseCase(tenantRepository);
    }

    @Bean
    public CreateUserUseCase createUserUseCase(
            UserRepository userRepository, TenantRepository tenantRepository, PasswordHasher passwordHasher) {
        return new CreateUserUseCase(userRepository, tenantRepository, passwordHasher);
    }

    @Bean
    public ResolveActiveTenantBySlugUseCase resolveActiveTenantBySlugUseCase(TenantRepository tenantRepository) {
        return new ResolveActiveTenantBySlugUseCase(tenantRepository);
    }

    @Bean
    public RegisterUserUseCase registerUserUseCase(
            CreateUserUseCase createUserUseCase,
            VerificationTokenRepository verificationTokenRepository,
            VerificationTokenHasher verificationTokenHasher,
            EmailSender emailSender) {
        return new RegisterUserUseCase(
                createUserUseCase, verificationTokenRepository, verificationTokenHasher, emailSender);
    }

    @Bean
    public VerifyEmailUseCase verifyEmailUseCase(
            VerificationTokenRepository verificationTokenRepository,
            VerificationTokenHasher verificationTokenHasher,
            UserRepository userRepository) {
        return new VerifyEmailUseCase(verificationTokenRepository, verificationTokenHasher, userRepository);
    }

    @Bean
    public LoginUseCase loginUseCase(UserRepository userRepository, PasswordHasher passwordHasher) {
        return new LoginUseCase(userRepository, passwordHasher);
    }

    @Bean
    public RequestPasswordResetUseCase requestPasswordResetUseCase(
            UserRepository userRepository,
            PasswordResetTokenRepository passwordResetTokenRepository,
            VerificationTokenHasher verificationTokenHasher,
            EmailSender emailSender) {
        return new RequestPasswordResetUseCase(
                userRepository, passwordResetTokenRepository, verificationTokenHasher, emailSender);
    }

    @Bean
    public ResetPasswordUseCase resetPasswordUseCase(
            PasswordResetTokenRepository passwordResetTokenRepository,
            VerificationTokenHasher verificationTokenHasher,
            UserRepository userRepository,
            PasswordHasher passwordHasher) {
        return new ResetPasswordUseCase(
                passwordResetTokenRepository, verificationTokenHasher, userRepository, passwordHasher);
    }

    @Bean
    public ChangePasswordUseCase changePasswordUseCase(UserRepository userRepository, PasswordHasher passwordHasher) {
        return new ChangePasswordUseCase(userRepository, passwordHasher);
    }

    @Bean
    public GenerateSigningKeyUseCase generateSigningKeyUseCase(
            TenantRepository tenantRepository,
            SigningKeyRepository signingKeyRepository,
            SigningKeyPairGenerator signingKeyPairGenerator,
            PrivateKeyEncryptor privateKeyEncryptor) {
        return new GenerateSigningKeyUseCase(
                tenantRepository, signingKeyRepository, signingKeyPairGenerator, privateKeyEncryptor);
    }

    @Bean
    public ListSigningKeysUseCase listSigningKeysUseCase(SigningKeyRepository signingKeyRepository) {
        return new ListSigningKeysUseCase(signingKeyRepository);
    }

    @Bean
    public AuthorizeUseCase authorizeUseCase(
            OAuthClientRepository oauthClientRepository,
            AuthorizationCodeRepository authorizationCodeRepository,
            VerificationTokenHasher verificationTokenHasher) {
        return new AuthorizeUseCase(oauthClientRepository, authorizationCodeRepository, verificationTokenHasher);
    }

    @Bean
    public TokenUseCase tokenUseCase(
            OAuthClientRepository oauthClientRepository,
            ClientSecretHasher clientSecretHasher,
            AuthorizationCodeRepository authorizationCodeRepository,
            VerificationTokenHasher verificationTokenHasher,
            CodeVerifierValidator codeVerifierValidator,
            SigningKeyRepository signingKeyRepository,
            PrivateKeyEncryptor privateKeyEncryptor,
            JwtSigner jwtSigner) {
        return new TokenUseCase(
                oauthClientRepository,
                clientSecretHasher,
                authorizationCodeRepository,
                verificationTokenHasher,
                codeVerifierValidator,
                signingKeyRepository,
                privateKeyEncryptor,
                jwtSigner);
    }
}
