package com.ssoplatform.idp.application.usecase.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.domain.mfa.EncryptedTotpSecret;
import com.ssoplatform.idp.domain.mfa.TotpCredential;
import com.ssoplatform.idp.domain.user.UserId;
import java.time.Instant;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class GetMfaStatusUseCaseTest {

    @Mock
    private TotpCredentialRepository totpCredentialRepository;

    private GetMfaStatusUseCase useCase;
    private UserId userId;

    @BeforeEach
    void setUp() {
        useCase = new GetMfaStatusUseCase(totpCredentialRepository);
        userId = UserId.generate();
    }

    @Test
    void reportsEnabledWhenAnActiveCredentialExists() {
        TotpCredential active =
                TotpCredential.enroll(userId, EncryptedTotpSecret.of("Y2lwaGVydGV4dA=="), Instant.now());
        active.activate(Instant.now());
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.of(active));

        assertThat(useCase.execute(new GetMfaStatusQuery(userId.value())).enabled()).isTrue();
    }

    @Test
    void reportsDisabledWhenNoCredentialExists() {
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.empty());

        assertThat(useCase.execute(new GetMfaStatusQuery(userId.value())).enabled()).isFalse();
    }

    @Test
    void reportsDisabledForAPendingUnconfirmedCredential() {
        TotpCredential pending =
                TotpCredential.enroll(userId, EncryptedTotpSecret.of("Y2lwaGVydGV4dA=="), Instant.now());
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.of(pending));

        assertThat(useCase.execute(new GetMfaStatusQuery(userId.value())).enabled()).isFalse();
    }
}
