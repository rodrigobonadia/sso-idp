package com.ssoplatform.idp.application.usecase.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.port.out.EmailSender;
import com.ssoplatform.idp.application.port.out.PasswordResetTokenRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.domain.passwordreset.PasswordResetToken;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RequestPasswordResetUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final HashedPassword PASSWORD_HASH = HashedPassword.of("$2a$10$somehashvalue");

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordResetTokenRepository passwordResetTokenRepository;

    @Mock
    private VerificationTokenHasher verificationTokenHasher;

    @Mock
    private EmailSender emailSender;

    private RequestPasswordResetUseCase useCase;

    @BeforeEach
    void setUp() {
        useCase = new RequestPasswordResetUseCase(
                userRepository, passwordResetTokenRepository, verificationTokenHasher, emailSender);
    }

    @Test
    void issuesAndSendsATokenWhenTheAccountExistsAndIsActive() {
        User user = User.register(TENANT_ID, Email.of("someone@example.com"), PASSWORD_HASH);
        user.verifyEmail();
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("someone@example.com")))
                .thenReturn(Optional.of(user));
        TokenHash tokenHash = TokenHash.of("some-hash-value");
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);

        useCase.execute(new RequestPasswordResetCommand(TENANT_ID.value(), "acme", "someone@example.com"));

        ArgumentCaptor<PasswordResetToken> tokenCaptor = ArgumentCaptor.forClass(PasswordResetToken.class);
        verify(passwordResetTokenRepository).save(tokenCaptor.capture());
        assertThat(tokenCaptor.getValue().userId()).isEqualTo(user.id());
        assertThat(tokenCaptor.getValue().tokenHash()).isEqualTo(tokenHash);
        verify(emailSender)
                .sendPasswordResetEmail(eq(Email.of("someone@example.com")), eq("acme"), any(RawVerificationToken.class));
    }

    @Test
    void issuesATokenForALockedAccount() {
        User user = User.register(TENANT_ID, Email.of("someone@example.com"), PASSWORD_HASH);
        user.verifyEmail();
        user.lock();
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("someone@example.com")))
                .thenReturn(Optional.of(user));
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("some-hash-value"));

        useCase.execute(new RequestPasswordResetCommand(TENANT_ID.value(), "acme", "someone@example.com"));

        verify(passwordResetTokenRepository).save(any());
        verify(emailSender).sendPasswordResetEmail(any(), eq("acme"), any());
    }

    @Test
    void issuesATokenForAnAccountPendingVerification() {
        User user = User.register(TENANT_ID, Email.of("someone@example.com"), PASSWORD_HASH);
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("someone@example.com")))
                .thenReturn(Optional.of(user));
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(TokenHash.of("some-hash-value"));

        useCase.execute(new RequestPasswordResetCommand(TENANT_ID.value(), "acme", "someone@example.com"));

        verify(passwordResetTokenRepository).save(any());
        verify(emailSender).sendPasswordResetEmail(any(), eq("acme"), any());
    }

    @Test
    void doesNotIssueATokenForADisabledAccountButDoesNotThrow() {
        User user = User.register(TENANT_ID, Email.of("someone@example.com"), PASSWORD_HASH);
        user.verifyEmail();
        user.disable();
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("someone@example.com")))
                .thenReturn(Optional.of(user));

        useCase.execute(new RequestPasswordResetCommand(TENANT_ID.value(), "acme", "someone@example.com"));

        verifyNoInteractions(passwordResetTokenRepository, emailSender);
    }

    @Test
    void doesNothingButDoesNotThrowWhenNoAccountMatchesTheEmail() {
        when(userRepository.findByTenantIdAndEmail(TENANT_ID, Email.of("nobody@example.com")))
                .thenReturn(Optional.empty());

        useCase.execute(new RequestPasswordResetCommand(TENANT_ID.value(), "acme", "nobody@example.com"));

        verifyNoInteractions(passwordResetTokenRepository, emailSender);
    }

    @Test
    void doesNothingButDoesNotThrowForAMalformedEmail() {
        useCase.execute(new RequestPasswordResetCommand(TENANT_ID.value(), "acme", "not-an-email"));

        verify(userRepository, never()).findByTenantIdAndEmail(any(), any());
        verifyNoInteractions(passwordResetTokenRepository, emailSender);
    }
}
