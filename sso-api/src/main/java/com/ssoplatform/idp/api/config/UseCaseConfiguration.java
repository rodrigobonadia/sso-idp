package com.ssoplatform.idp.api.config;

import com.ssoplatform.idp.application.port.out.EmailSender;
import com.ssoplatform.idp.application.port.out.PasswordHasher;
import com.ssoplatform.idp.application.port.out.TenantRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.application.port.out.VerificationTokenRepository;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantUseCase;
import com.ssoplatform.idp.application.usecase.tenant.ResolveActiveTenantBySlugUseCase;
import com.ssoplatform.idp.application.usecase.user.CreateUserUseCase;
import com.ssoplatform.idp.application.usecase.user.LoginUseCase;
import com.ssoplatform.idp.application.usecase.user.RegisterUserUseCase;
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
}
