package com.ssoplatform.idp.infrastructure.persistence.adapter;

import com.ssoplatform.idp.application.port.out.DeviceCodeRepository;
import com.ssoplatform.idp.domain.devicecode.DeviceCode;
import com.ssoplatform.idp.domain.devicecode.UserCode;
import com.ssoplatform.idp.domain.verification.TokenHash;
import com.ssoplatform.idp.infrastructure.persistence.entity.DeviceCodeJpaEntity;
import com.ssoplatform.idp.infrastructure.persistence.mapper.DeviceCodeEntityMapper;
import com.ssoplatform.idp.infrastructure.persistence.repository.DeviceCodeJpaRepository;
import java.util.Optional;
import org.springframework.stereotype.Repository;

/** Adapter implementing the {@link DeviceCodeRepository} output port on top of Spring Data JPA. */
@Repository
public class DeviceCodeRepositoryAdapter implements DeviceCodeRepository {

    private final DeviceCodeJpaRepository jpaRepository;

    public DeviceCodeRepositoryAdapter(DeviceCodeJpaRepository jpaRepository) {
        this.jpaRepository = jpaRepository;
    }

    @Override
    public DeviceCode save(DeviceCode deviceCode) {
        DeviceCodeJpaEntity saved = jpaRepository.save(DeviceCodeEntityMapper.toEntity(deviceCode));
        return DeviceCodeEntityMapper.toDomain(saved);
    }

    @Override
    public Optional<DeviceCode> findByDeviceCodeHash(TokenHash deviceCodeHash) {
        return jpaRepository.findByDeviceCodeHash(deviceCodeHash.value()).map(DeviceCodeEntityMapper::toDomain);
    }

    @Override
    public Optional<DeviceCode> findByUserCode(UserCode userCode) {
        return jpaRepository.findByUserCode(userCode.value()).map(DeviceCodeEntityMapper::toDomain);
    }
}
