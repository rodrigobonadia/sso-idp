package com.ssoplatform.idp.application.usecase.mfa;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.port.out.EmailOtpCredentialRepository;
import com.ssoplatform.idp.application.port.out.TotpCredentialRepository;
import com.ssoplatform.idp.domain.mfa.EmailOtpCredential;
import com.ssoplatform.idp.domain.mfa.EncryptedTotpSecret;
import com.ssoplatform.idp.domain.mfa.MfaMethod;
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

    @Mock
    private EmailOtpCredentialRepository emailOtpCredentialRepository;

    private GetMfaStatusUseCase useCase;
    private UserId userId;

    @BeforeEach
    void setUp() {
        useCase = new GetMfaStatusUseCase(totpCredentialRepository, emailOtpCredentialRepository);
        userId = UserId.generate();
    }

    @Test
    void reportsEnabledWithTotpWhenAnActiveTotpCredentialExists() {
        TotpCredential active =
                TotpCredential.enroll(userId, EncryptedTotpSecret.of("Y2lwaGVydGV4dA=="), Instant.now());
        active.activate(Instant.now());
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.of(active));

        GetMfaStatusResult result = useCase.execute(new GetMfaStatusQuery(userId.value()));

        assertThat(result.enabled()).isTrue();
        assertThat(result.method()).isEqualTo(MfaMethod.TOTP);
    }

    @Test
    void reportsEnabledWithEmailOtpWhenAnActiveEmailOtpCredentialExistsAndNoTotpDoes() {
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.empty());
        EmailOtpCredential active = EmailOtpCredential.enable(userId, Instant.now());
        active.activate(Instant.now());
        when(emailOtpCredentialRepository.findByUserId(userId)).thenReturn(Optional.of(active));

        GetMfaStatusResult result = useCase.execute(new GetMfaStatusQuery(userId.value()));

        assertThat(result.enabled()).isTrue();
        assertThat(result.method()).isEqualTo(MfaMethod.EMAIL_OTP);
    }

    @Test
    void reportsDisabledWhenNoCredentialOfEitherMethodExists() {
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.empty());
        when(emailOtpCredentialRepository.findByUserId(userId)).thenReturn(Optional.empty());

        GetMfaStatusResult result = useCase.execute(new GetMfaStatusQuery(userId.value()));

        assertThat(result.enabled()).isFalse();
        assertThat(result.method()).isNull();
    }

    @Test
    void reportsDisabledForAPendingUnconfirmedTotpCredential() {
        TotpCredential pending =
                TotpCredential.enroll(userId, EncryptedTotpSecret.of("Y2lwaGVydGV4dA=="), Instant.now());
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.of(pending));
        when(emailOtpCredentialRepository.findByUserId(userId)).thenReturn(Optional.empty());

        assertThat(useCase.execute(new GetMfaStatusQuery(userId.value())).enabled()).isFalse();
    }

    @Test
    void reportsDisabledForAPendingUnconfirmedEmailOtpCredential() {
        when(totpCredentialRepository.findByUserId(userId)).thenReturn(Optional.empty());
        EmailOtpCredential pending = EmailOtpCredential.enable(userId, Instant.now());
        when(emailOtpCredentialRepository.findByUserId(userId)).thenReturn(Optional.of(pending));

        assertThat(useCase.execute(new GetMfaStatusQuery(userId.value())).enabled()).isFalse();
    }
}
