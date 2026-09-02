package com.ssoplatform.idp.application.usecase.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.DuplicateEmailException;
import com.ssoplatform.idp.application.port.out.EmailSender;
import com.ssoplatform.idp.application.port.out.VerificationTokenHasher;
import com.ssoplatform.idp.application.port.out.VerificationTokenRepository;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.verification.EmailVerificationToken;
import com.ssoplatform.idp.domain.verification.RawVerificationToken;
import com.ssoplatform.idp.domain.verification.TokenHash;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class RegisterUserUseCaseTest {

    @Mock
    private CreateUserUseCase createUserUseCase;

    @Mock
    private VerificationTokenRepository verificationTokenRepository;

    @Mock
    private VerificationTokenHasher verificationTokenHasher;

    @Mock
    private EmailSender emailSender;

    private RegisterUserUseCase useCase;

    @BeforeEach
    void setUp() {
        useCase = new RegisterUserUseCase(
                createUserUseCase, verificationTokenRepository, verificationTokenHasher, emailSender);
    }

    @Test
    void createsTheUserThenIssuesAndSendsAVerificationToken() {
        UUID tenantId = UUID.randomUUID();
        UUID userId = UUID.randomUUID();
        CreateUserResult createResult = new CreateUserResult(userId, tenantId, "someone@example.com");
        when(createUserUseCase.execute(
                        new CreateUserCommand(tenantId, "someone@example.com", "Jane", "Doe", "Str0ng!Passw0rd")))
                .thenReturn(createResult);
        TokenHash tokenHash = TokenHash.of("some-hash-value");
        when(verificationTokenHasher.hash(any(RawVerificationToken.class))).thenReturn(tokenHash);

        RegisterUserResult result = useCase.execute(new RegisterUserCommand(
                tenantId, "acme", "someone@example.com", "Jane", "Doe", "Str0ng!Passw0rd"));

        assertThat(result.userId()).isEqualTo(userId);
        assertThat(result.tenantId()).isEqualTo(tenantId);
        assertThat(result.email()).isEqualTo("someone@example.com");

        ArgumentCaptor<EmailVerificationToken> tokenCaptor = ArgumentCaptor.forClass(EmailVerificationToken.class);
        verify(verificationTokenRepository).save(tokenCaptor.capture());
        assertThat(tokenCaptor.getValue().userId().value()).isEqualTo(userId);
        assertThat(tokenCaptor.getValue().tokenHash()).isEqualTo(tokenHash);

        verify(emailSender)
                .sendVerificationEmail(
                        eq(Email.of("someone@example.com")), eq("acme"), any(RawVerificationToken.class));
    }

    @Test
    void propagatesFailuresFromUserCreationWithoutIssuingAToken() {
        UUID tenantId = UUID.randomUUID();
        when(createUserUseCase.execute(any(CreateUserCommand.class)))
                .thenThrow(new DuplicateEmailException("someone@example.com"));

        assertThatThrownBy(() -> useCase.execute(new RegisterUserCommand(
                        tenantId, "acme", "someone@example.com", "Jane", "Doe", "Str0ng!Passw0rd")))
                .isInstanceOf(DuplicateEmailException.class);

        verifyNoInteractions(verificationTokenRepository, emailSender);
        verify(verificationTokenHasher, never()).hash(any());
    }
}
