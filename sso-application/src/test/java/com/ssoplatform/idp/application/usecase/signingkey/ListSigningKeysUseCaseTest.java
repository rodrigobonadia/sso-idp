package com.ssoplatform.idp.application.usecase.signingkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.port.out.SigningKeyRepository;
import com.ssoplatform.idp.domain.signingkey.EncryptedPrivateKeyMaterial;
import com.ssoplatform.idp.domain.signingkey.KeyId;
import com.ssoplatform.idp.domain.signingkey.PublicKeyMaterial;
import com.ssoplatform.idp.domain.signingkey.SigningKey;
import com.ssoplatform.idp.domain.tenant.TenantId;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class ListSigningKeysUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();

    @Mock
    private SigningKeyRepository signingKeyRepository;

    private ListSigningKeysUseCase useCase;

    @BeforeEach
    void setUp() {
        useCase = new ListSigningKeysUseCase(signingKeyRepository);
    }

    @Test
    void returnsEveryKeyForTheTenantRegardlessOfStatus() {
        SigningKey current = SigningKey.generate(
                TENANT_ID, KeyId.generate(), PublicKeyMaterial.of("Y3VycmVudA=="), EncryptedPrivateKeyMaterial.of("YQ=="));
        SigningKey retired = SigningKey.generate(
                TENANT_ID, KeyId.generate(), PublicKeyMaterial.of("cmV0aXJlZA=="), EncryptedPrivateKeyMaterial.of("Yg=="));
        retired.retire();
        when(signingKeyRepository.findAllByTenantId(TENANT_ID)).thenReturn(List.of(current, retired));

        List<SigningKeySummary> result = useCase.execute(new ListSigningKeysQuery(TENANT_ID.value()));

        assertThat(result).hasSize(2);
        assertThat(result)
                .extracting(SigningKeySummary::kid)
                .containsExactlyInAnyOrder(current.kid().value(), retired.kid().value());
        assertThat(result).extracting(SigningKeySummary::algorithm).containsOnly(SigningKey.ALGORITHM);
        assertThat(result)
                .extracting(SigningKeySummary::publicKeyDer)
                .containsExactlyInAnyOrder("Y3VycmVudA==", "cmV0aXJlZA==");
    }

    @Test
    void returnsAnEmptyListWhenTheTenantHasNoSigningKeysYet() {
        when(signingKeyRepository.findAllByTenantId(TENANT_ID)).thenReturn(List.of());

        assertThat(useCase.execute(new ListSigningKeysQuery(TENANT_ID.value()))).isEmpty();
    }
}
