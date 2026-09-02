package com.ssoplatform.idp.domain.user;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.ssoplatform.idp.domain.tenant.TenantId;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class UserTest {

    private final TenantId tenantId = TenantId.generate();
    private final Email email = Email.of("someone@example.com");
    private final PersonName givenName = PersonName.of("Jane");
    private final PersonName familyName = PersonName.of("Doe");
    private final HashedPassword passwordHash = HashedPassword.of("$2a$10$somehashvalue");

    @Test
    void registerCreatesAUserPendingEmailVerification() {
        User user = User.register(tenantId, email, givenName, familyName, passwordHash);

        assertThat(user.id()).isNotNull();
        assertThat(user.tenantId()).isEqualTo(tenantId);
        assertThat(user.email()).isEqualTo(email);
        assertThat(user.givenName()).isEqualTo(givenName);
        assertThat(user.familyName()).isEqualTo(familyName);
        assertThat(user.passwordHash()).isEqualTo(passwordHash);
        assertThat(user.status()).isEqualTo(UserStatus.PENDING_VERIFICATION);
        assertThat(user.failedLoginAttempts()).isZero();
        assertThat(user.canAuthenticate()).isFalse();
    }

    @Test
    void verifyEmailActivatesAPendingUser() {
        User user = User.register(tenantId, email, givenName, familyName, passwordHash);

        user.verifyEmail();

        assertThat(user.status()).isEqualTo(UserStatus.ACTIVE);
        assertThat(user.canAuthenticate()).isTrue();
    }

    @Test
    void verifyEmailOnAnAlreadyActiveUserThrows() {
        User user = User.register(tenantId, email, givenName, familyName, passwordHash);
        user.verifyEmail();

        assertThatThrownBy(user::verifyEmail).isInstanceOf(UserStateException.class);
    }

    @Test
    void changePasswordReplacesTheHash() {
        User user = User.register(tenantId, email, givenName, familyName, passwordHash);
        HashedPassword newHash = HashedPassword.of("$2a$10$anotherhash");

        user.changePassword(newHash);

        assertThat(user.passwordHash()).isEqualTo(newHash);
    }

    @Test
    void changePasswordOnADisabledUserThrows() {
        User user = activeUser();
        user.disable();

        assertThatThrownBy(() -> user.changePassword(HashedPassword.of("$2a$10$anotherhash")))
                .isInstanceOf(UserStateException.class);
    }

    @Test
    void recordFailedLoginIncrementsTheCounter() {
        User user = activeUser();

        user.recordFailedLogin();
        user.recordFailedLogin();

        assertThat(user.failedLoginAttempts()).isEqualTo(2);
        assertThat(user.status()).isEqualTo(UserStatus.ACTIVE);
    }

    @Test
    void recordFailedLoginLocksTheAccountAfterFiveAttempts() {
        User user = activeUser();

        for (int i = 0; i < User.MAX_FAILED_LOGIN_ATTEMPTS; i++) {
            user.recordFailedLogin();
        }

        assertThat(user.status()).isEqualTo(UserStatus.LOCKED);
        assertThat(user.failedLoginAttempts()).isEqualTo(User.MAX_FAILED_LOGIN_ATTEMPTS);
    }

    @Test
    void recordSuccessfulLoginResetsTheCounter() {
        User user = activeUser();
        user.recordFailedLogin();
        user.recordFailedLogin();

        user.recordSuccessfulLogin();

        assertThat(user.failedLoginAttempts()).isZero();
    }

    @Test
    void recordSuccessfulLoginOnANonActiveUserThrows() {
        User user = User.register(tenantId, email, givenName, familyName, passwordHash); // PENDING_VERIFICATION

        assertThatThrownBy(user::recordSuccessfulLogin).isInstanceOf(UserStateException.class);
    }

    @Test
    void lockTransitionsAnActiveUserToLocked() {
        User user = activeUser();

        user.lock();

        assertThat(user.status()).isEqualTo(UserStatus.LOCKED);
    }

    @Test
    void lockingAnAlreadyLockedUserThrows() {
        User user = activeUser();
        user.lock();

        assertThatThrownBy(user::lock).isInstanceOf(UserStateException.class);
    }

    @Test
    void unlockTransitionsALockedUserBackToActiveAndResetsCounter() {
        User user = activeUser();
        user.lock();

        user.unlock();

        assertThat(user.status()).isEqualTo(UserStatus.ACTIVE);
        assertThat(user.failedLoginAttempts()).isZero();
    }

    @Test
    void unlockingANonLockedUserThrows() {
        User user = activeUser();

        assertThatThrownBy(user::unlock).isInstanceOf(UserStateException.class);
    }

    @Test
    void disableTransitionsAnyNonDisabledUserToDisabled() {
        User user = activeUser();

        user.disable();

        assertThat(user.status()).isEqualTo(UserStatus.DISABLED);
        assertThat(user.canAuthenticate()).isFalse();
    }

    @Test
    void disablingAnAlreadyDisabledUserThrows() {
        User user = activeUser();
        user.disable();

        assertThatThrownBy(user::disable).isInstanceOf(UserStateException.class);
    }

    @Test
    void enableTransitionsADisabledUserBackToActiveAndResetsCounter() {
        User user = activeUser();
        user.disable();

        user.enable();

        assertThat(user.status()).isEqualTo(UserStatus.ACTIVE);
        assertThat(user.failedLoginAttempts()).isZero();
    }

    @Test
    void enablingANonDisabledUserThrows() {
        User user = activeUser();

        assertThatThrownBy(user::enable).isInstanceOf(UserStateException.class);
    }

    @Test
    void reconstituteRebuildsAnExistingUserWithoutRunningRegistrationLogic() {
        User user = User.reconstitute(
                UserId.generate(),
                tenantId,
                email,
                givenName,
                familyName,
                passwordHash,
                UserStatus.LOCKED,
                3,
                Instant.now());

        assertThat(user.status()).isEqualTo(UserStatus.LOCKED);
        assertThat(user.failedLoginAttempts()).isEqualTo(3);
        assertThat(user.givenName()).isEqualTo(givenName);
        assertThat(user.familyName()).isEqualTo(familyName);
    }

    @Test
    void reconstituteRejectsNegativeFailedLoginAttempts() {
        assertThatThrownBy(() -> User.reconstitute(
                        UserId.generate(),
                        tenantId,
                        email,
                        givenName,
                        familyName,
                        passwordHash,
                        UserStatus.ACTIVE,
                        -1,
                        Instant.now()))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void equalityIsBasedOnId() {
        UserId id = UserId.generate();
        Instant now = Instant.now();
        User first = User.reconstitute(
                id, tenantId, email, givenName, familyName, passwordHash, UserStatus.ACTIVE, 0, now);
        User second = User.reconstitute(
                id,
                tenantId,
                Email.of("other@example.com"),
                PersonName.of("Other"),
                PersonName.of("Person"),
                passwordHash,
                UserStatus.LOCKED,
                2,
                now);

        assertThat(first).isEqualTo(second);
        assertThat(first).hasSameHashCodeAs(second);
    }

    private User activeUser() {
        User user = User.register(tenantId, email, givenName, familyName, passwordHash);
        user.verifyEmail();
        return user;
    }
}
