package com.ssoplatform.idp.infrastructure.persistence.repository;

import com.ssoplatform.idp.infrastructure.persistence.entity.DeviceCodeJpaEntity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

/** Spring Data JPA repository. Not exposed outside the infrastructure layer directly. */
public interface DeviceCodeJpaRepository extends JpaRepository<DeviceCodeJpaEntity, UUID> {

    Optional<DeviceCodeJpaEntity> findByDeviceCodeHash(String deviceCodeHash);

    Optional<DeviceCodeJpaEntity> findByUserCode(String userCode);
}
