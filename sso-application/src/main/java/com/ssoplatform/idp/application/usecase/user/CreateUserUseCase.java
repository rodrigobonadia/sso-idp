package com.ssoplatform.idp.application.usecase.user;

import com.ssoplatform.idp.application.exception.DuplicateEmailException;
import com.ssoplatform.idp.application.exception.TenantNotActiveException;
import com.ssoplatform.idp.application.exception.TenantNotFoundException;
import com.ssoplatform.idp.application.port.out.PasswordHasher;
import com.ssoplatform.idp.application.port.out.TenantRepository;
import com.ssoplatform.idp.application.port.out.UserRepository;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.user.Email;
import com.ssoplatform.idp.domain.user.HashedPassword;
import com.ssoplatform.idp.domain.user.PersonName;
import com.ssoplatform.idp.domain.user.RawPassword;
import com.ssoplatform.idp.domain.user.User;
import java.util.Objects;

/**
 * Registers a new user under an existing, active tenant.
 *
 * <p>Orchestrates three ports: {@link TenantRepository} (to check the tenant exists and is
 * active), {@link UserRepository} (to check e-mail uniqueness within the tenant and persist),
 * and {@link PasswordHasher} (to turn the caller-supplied plaintext password into a
 * {@link HashedPassword} without the domain ever knowing which algorithm was used).
 */
public class CreateUserUseCase {

    private final UserRepository userRepository;
    private final TenantRepository tenantRepository;
    private final PasswordHasher passwordHasher;

    public CreateUserUseCase(
            UserRepository userRepository, TenantRepository tenantRepository, PasswordHasher passwordHasher) {
        this.userRepository = Objects.requireNonNull(userRepository, "userRepository must not be null");
        this.tenantRepository = Objects.requireNonNull(tenantRepository, "tenantRepository must not be null");
        this.passwordHasher = Objects.requireNonNull(passwordHasher, "passwordHasher must not be null");
    }

    public CreateUserResult execute(CreateUserCommand command) {
        Objects.requireNonNull(command, "command must not be null");

        TenantId tenantId = TenantId.of(command.tenantId());
        Tenant tenant = tenantRepository.findById(tenantId).orElseThrow(() -> new TenantNotFoundException(
                command.tenantId()));
        if (!tenant.isActive()) {
            throw new TenantNotActiveException(tenant.slug().value());
        }

        Email email = Email.of(command.email());
        if (userRepository.existsByTenantIdAndEmail(tenantId, email)) {
            throw new DuplicateEmailException(email.value());
        }

        PersonName givenName = PersonName.of(command.givenName());
        PersonName familyName = PersonName.of(command.familyName());
        RawPassword rawPassword = RawPassword.of(command.rawPassword());
        HashedPassword hashedPassword = passwordHasher.hash(rawPassword);

        User user = User.register(tenantId, email, givenName, familyName, hashedPassword);
        User saved = userRepository.save(user);

        return new CreateUserResult(saved.id().value(), saved.tenantId().value(), saved.email().value());
    }
}
