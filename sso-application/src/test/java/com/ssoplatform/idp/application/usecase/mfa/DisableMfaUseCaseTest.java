package com.ssoplatform.idp.application.usecase.mfa;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.IncorrectCurrentPasswordException;
import com.ssoplatform.idp.application.exception.MfaNotEnabledException;
import com.ssoplatform.idp.application.exception.UserNotFoundException;
import com.ssoplatform.idp.application.port.out.PasswordHasher;
import com.ssoplatform.idp.application.port.out.RecoveryCodeRepository;
import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.domain.mfa.EncryptedTotpSecret;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.User;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class DisableMfaUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final HashedPassword PASSWORD_HASH = HashedPassword.of("$2a$10$somehashvalue");

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordHasher passwordHasher;

    @Mock
    private TotpCredentialRepository totpCredentialRepository;

    @Mock
    private RecoveryCodeRepository recoveryCodeRepository;

    private DisableMfaUseCase useCase;
    private User user;

    @BeforeEach
    void setUp() {
        useCase = new DisableMfaUseCase(userRepository, passwordHasher, totpCredentialRepository, recoveryCodeRepository);
        user = User.register(
                TENANT_ID, Email.of("someone@example.com"), PersonName.of("Jane"), PersonName.of("Doe"), PASSWORD_HASH);
    }

    @Test
    void disablesMfaForACorrectPasswordAndAnExistingCredential() {
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));
        when(passwordHasher.matches(eq("Str0ng!Passw0rd"), eq(PASSWORD_HASH))).thenReturn(true);
        when(totpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.of(
                TotpCredential.enroll(user.id(), EncryptedTotpSecret.of("Y2lwaGVydGV4dA=="), Instant.now())));

        useCase.execute(new DisableMfaCommand(user.id().value(), "Str0ng!Passw0rd"));

        verify(totpCredentialRepository).deleteByUserId(user.id());
        verify(recoveryCodeRepository).deleteAllByUserId(user.id());
    }

    @Test
    void rejectsAWrongCurrentPasswordAndTouchesNothing() {
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));
        when(passwordHasher.matches(eq("wrong-password"), eq(PASSWORD_HASH))).thenReturn(false);

        assertThatThrownBy(() -> useCase.execute(new DisableMfaCommand(user.id().value(), "wrong-password")))
                .isInstanceOf(IncorrectCurrentPasswordException.class);

        verify(totpCredentialRepository, never()).deleteByUserId(any());
        verify(recoveryCodeRepository, never()).deleteAllByUserId(any());
    }

    @Test
    void rejectsDisablingWhenNoCredentialExists() {
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));
        when(passwordHasher.matches(eq("Str0ng!Passw0rd"), eq(PASSWORD_HASH))).thenReturn(true);
        when(totpCredentialRepository.findByUserId(user.id())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new DisableMfaCommand(user.id().value(), "Str0ng!Passw0rd")))
                .isInstanceOf(MfaNotEnabledException.class);

        verify(totpCredentialRepository, never()).deleteByUserId(any());
    }

    @Test
    void surfacesUserNotFoundForAnUnknownUserId() {
        when(userRepository.findById(user.id())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new DisableMfaCommand(user.id().value(), "whatever")))
                .isInstanceOf(UserNotFoundException.class);
    }
}
