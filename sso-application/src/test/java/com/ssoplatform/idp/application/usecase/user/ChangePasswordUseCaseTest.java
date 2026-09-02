package com.ssoplatform.idp.application.usecase.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.IncorrectCurrentPasswordException;
import com.ssoplatform.idp.application.exception.UserNotFoundException;
import com.ssoplatform.idp.application.port.out.PasswordHasher;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.User;
import com.ssoplatform.idp.domain.user.WeakPasswordException;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ChangePasswordUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();
    private static final HashedPassword OLD_PASSWORD_HASH = HashedPassword.of("$2a$10$oldhashvalue");
    private static final HashedPassword NEW_PASSWORD_HASH = HashedPassword.of("$2a$10$newhashvalue");

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordHasher passwordHasher;

    private ChangePasswordUseCase useCase;
    private User user;

    @BeforeEach
    void setUp() {
        useCase = new ChangePasswordUseCase(userRepository, passwordHasher);
        user = User.register(
                TENANT_ID,
                Email.of("someone@example.com"),
                PersonName.of("Jane"),
                PersonName.of("Doe"),
                OLD_PASSWORD_HASH);
        user.verifyEmail();
        when(userRepository.findById(user.id())).thenReturn(Optional.of(user));
    }

    @Test
    void changesThePasswordWhenTheCurrentPasswordMatches() {
        when(passwordHasher.matches("CurrentStr0ng!Pass", OLD_PASSWORD_HASH)).thenReturn(true);
        when(passwordHasher.hash(any())).thenReturn(NEW_PASSWORD_HASH);
        when(userRepository.save(user)).thenReturn(user);

        ChangePasswordResult result = useCase.execute(
                new ChangePasswordCommand(user.id().value(), "CurrentStr0ng!Pass", "N3wStr0ng!Passw0rd"));

        assertThat(result.userId()).isEqualTo(user.id().value());
        assertThat(result.email()).isEqualTo("someone@example.com");
        assertThat(user.passwordHash()).isEqualTo(NEW_PASSWORD_HASH);
        verify(userRepository).save(user);
    }

    @Test
    void rejectsAnIncorrectCurrentPasswordWithoutTouchingTheUser() {
        when(passwordHasher.matches(eq("WrongCurrentPass!1"), eq(OLD_PASSWORD_HASH))).thenReturn(false);

        assertThatThrownBy(() -> useCase.execute(
                        new ChangePasswordCommand(user.id().value(), "WrongCurrentPass!1", "N3wStr0ng!Passw0rd")))
                .isInstanceOf(IncorrectCurrentPasswordException.class);

        verify(userRepository, never()).save(any());
    }

    @Test
    void rejectsAWeakNewPasswordEvenWhenTheCurrentPasswordIsCorrect() {
        when(passwordHasher.matches("CurrentStr0ng!Pass", OLD_PASSWORD_HASH)).thenReturn(true);

        assertThatThrownBy(() ->
                        useCase.execute(new ChangePasswordCommand(user.id().value(), "CurrentStr0ng!Pass", "weak")))
                .isInstanceOf(WeakPasswordException.class);

        verify(userRepository, never()).save(any());
    }

    @Test
    void surfacesADefensiveUserNotFoundExceptionWhenTheUserIdMatchesNoUser() {
        when(userRepository.findById(user.id())).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(
                        new ChangePasswordCommand(user.id().value(), "CurrentStr0ng!Pass", "N3wStr0ng!Passw0rd")))
                .isInstanceOf(UserNotFoundException.class);
    }
}
