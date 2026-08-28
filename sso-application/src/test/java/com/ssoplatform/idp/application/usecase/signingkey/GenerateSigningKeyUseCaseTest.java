package com.ssoplatform.idp.application.usecase.signingkey;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.ssoplatform.idp.application.exception.TenantNotFoundException;
import com.ssoplatform.idp.application.port.out.GeneratedKeyPair;
import com.ssoplatform.idp.application.port.out.PrivateKeyEncryptor;
import com.ssoplatform.idp.application.port.out.SigningKeyPairGenerator;
import com.ssoplatform.idp.application.port.out.SigningKeyRepository;
import com.ssoplatform.idp.application.port.out.TenantRepository;
import com.ssoplatform.idp.domain.signingkey.EncryptedPrivateKeyMaterial;
import com.ssoplatform.idp.domain.signingkey.KeyId;
import com.ssoplatform.idp.domain.signingkey.PublicKeyMaterial;
import com.ssoplatform.idp.domain.signingkey.SigningKey;
import com.ssoplatform.idp.domain.tenant.Tenant;
import com.ssoplatform.idp.domain.tenant.TenantId;
import com.ssoplatform.idp.domain.tenant.TenantSlug;
import java.util.Optional;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

@ExtendWith(MockitoExtension.class)
class GenerateSigningKeyUseCaseTest {

    private static final TenantId TENANT_ID = TenantId.generate();

    @Mock
    private TenantRepository tenantRepository;

    @Mock
    private SigningKeyRepository signingKeyRepository;

    @Mock
    private SigningKeyPairGenerator keyPairGenerator;

    @Mock
    private PrivateKeyEncryptor privateKeyEncryptor;

    private GenerateSigningKeyUseCase useCase;

    @BeforeEach
    void setUp() {
        useCase = new GenerateSigningKeyUseCase(
                tenantRepository, signingKeyRepository, keyPairGenerator, privateKeyEncryptor);
    }

    @Test
    void generatesAndSavesANewCurrentKeyWhenTheTenantHasNoneYet() {
        Tenant tenant = Tenant.create("Acme Corp", TenantSlug.of("acme"));
        when(tenantRepository.findById(TENANT_ID)).thenReturn(Optional.of(tenant));
        when(signingKeyRepository.findCurrentByTenantId(TENANT_ID)).thenReturn(Optional.empty());
        when(keyPairGenerator.generate())
                .thenReturn(new GeneratedKeyPair(new byte[] {1, 2, 3}, new byte[] {4, 5, 6}));
        when(privateKeyEncryptor.encrypt(any(byte[].class)))
                .thenReturn(EncryptedPrivateKeyMaterial.of("ZW5jcnlwdGVk"));
        when(signingKeyRepository.save(any(SigningKey.class))).thenAnswer(invocation -> invocation.getArgument(0));

        GenerateSigningKeyResult result = useCase.execute(new GenerateSigningKeyCommand(TENANT_ID.value()));

        assertThat(result.tenantId()).isEqualTo(TENANT_ID.value());
        assertThat(result.kid()).isNotBlank();
        assertThat(result.createdAt()).isNotNull();
        verify(signingKeyRepository, times(1)).save(any(SigningKey.class));
    }

    @Test
    void retiresTheExistingCurrentKeyBeforeSavingTheNewOne() {
        Tenant tenant = Tenant.create("Acme Corp", TenantSlug.of("acme"));
        when(tenantRepository.findById(TENANT_ID)).thenReturn(Optional.of(tenant));

        // A real (not mocked) key: SigningKey is final, and retire() mutates it in place, so
        // asserting on this exact reference after execute() proves the use case retired it.
        SigningKey existingCurrent = SigningKey.generate(
                TENANT_ID, KeyId.generate(), PublicKeyMaterial.of("b2xk"), EncryptedPrivateKeyMaterial.of("b2xk"));
        when(signingKeyRepository.findCurrentByTenantId(TENANT_ID)).thenReturn(Optional.of(existingCurrent));
        when(keyPairGenerator.generate())
                .thenReturn(new GeneratedKeyPair(new byte[] {1, 2, 3}, new byte[] {4, 5, 6}));
        when(privateKeyEncryptor.encrypt(any(byte[].class)))
                .thenReturn(EncryptedPrivateKeyMaterial.of("ZW5jcnlwdGVk"));
        when(signingKeyRepository.save(any(SigningKey.class))).thenAnswer(invocation -> invocation.getArgument(0));

        useCase.execute(new GenerateSigningKeyCommand(TENANT_ID.value()));

        assertThat(existingCurrent.isCurrent()).isFalse();
        verify(signingKeyRepository, times(1)).save(existingCurrent);
        verify(signingKeyRepository, times(2)).save(any(SigningKey.class));
    }

    @Test
    void rejectsAnUnknownTenantWithoutGeneratingAnyKeyMaterial() {
        when(tenantRepository.findById(TENANT_ID)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> useCase.execute(new GenerateSigningKeyCommand(TENANT_ID.value())))
                .isInstanceOf(TenantNotFoundException.class);

        verify(keyPairGenerator, never()).generate();
        verify(signingKeyRepository, never()).save(any());
    }
}
