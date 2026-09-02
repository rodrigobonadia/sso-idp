package com.ssoplatform.idp.application.usecase.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.DuplicateEmailException;
import com.ssoplatform.idp.application.exception.TenantNotActiveException;
import com.ssoplatform.idp.application.exception.TenantNotFoundException;
import com.ssoplatform.idp.application.port.out.PasswordHasher;
import com.ssoplatform.idp.application.port.out.TenantRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.RawPassword;
import com.ssoplatform.idp.domain.user.User;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class CreateUserUseCaseTest {

    private static final String RAW_PASSWORD = "Str0ng!Passw0rd";
    private static final String GIVEN_NAME = "Jane";
    private static final String FAMILY_NAME = "Doe";

    @Mock
    private UserRepository userRepository;

    @Mock
    private TenantRepository tenantRepository;

    @Mock
    private PasswordHasher passwordHasher;

    private CreateUserUseCase useCase;
    private Tenant activeTenant;

    @BeforeEach
    void setUp() {
        useCase = new CreateUserUseCase(userRepository, tenantRepository, passwordHasher);
        activeTenant = Tenant.create("Acme Corp", TenantSlug.of("acme"));
    }

    @Test
    void createsAndPersistsANewUserWhenTenantIsActiveAndEmailIsAvailable() {
        UUID tenantId = activeTenant.id().value();
        when(tenantRepository.findById(TenantId.of(tenantId))).thenReturn(Optional.of(activeTenant));
        when(userRepository.existsByTenantIdAndEmail(activeTenant.id(), Email.of("someone@example.com")))
                .thenReturn(false);
        HashedPassword hashedPassword = HashedPassword.of("$2a$10$somehashvalue");
        when(passwordHasher.hash(RawPassword.of(RAW_PASSWORD))).thenReturn(hashedPassword);
        when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0));

        CreateUserResult result = useCase.execute(
                new CreateUserCommand(tenantId, "Someone@Example.com", GIVEN_NAME, FAMILY_NAME, RAW_PASSWORD));

        assertThat(result.tenantId()).isEqualTo(tenantId);
        assertThat(result.email()).isEqualTo("someone@example.com");
        assertThat(result.userId()).isNotNull();
        verify(userRepository).save(any(User.class));
    }

    @Test
    void rejectsCreationWhenTenantDoesNotExist() {
        UUID unknownTenantId = UUID.randomUUID();
        when(tenantRepository.findById(TenantId.of(unknownTenantId))).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new CreateUserCommand(
                        unknownTenantId, "someone@example.com", GIVEN_NAME, FAMILY_NAME, RAW_PASSWORD)))
                .isInstanceOf(TenantNotFoundException.class);
    }

    @Test
    void rejectsCreationWhenTenantIsSuspended() {
        activeTenant.suspend();
        UUID tenantId = activeTenant.id().value();
        when(tenantRepository.findById(TenantId.of(tenantId))).thenReturn(Optional.of(activeTenant));

        assertThatThrownBy(() -> useCase.execute(
                        new CreateUserCommand(tenantId, "someone@example.com", GIVEN_NAME, FAMILY_NAME, RAW_PASSWORD)))
                .isInstanceOf(TenantNotActiveException.class);
    }

    @Test
    void rejectsCreationWhenEmailIsAlreadyRegisteredForTheTenant() {
        UUID tenantId = activeTenant.id().value();
        when(tenantRepository.findById(TenantId.of(tenantId))).thenReturn(Optional.of(activeTenant));
        when(userRepository.existsByTenantIdAndEmail(activeTenant.id(), Email.of("someone@example.com")))
                .thenReturn(true);

        assertThatThrownBy(() -> useCase.execute(
                        new CreateUserCommand(tenantId, "someone@example.com", GIVEN_NAME, FAMILY_NAME, RAW_PASSWORD)))
                .isInstanceOf(DuplicateEmailException.class);
    }
}
