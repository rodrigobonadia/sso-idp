package com.ssoplatform.idp.domain.devicecode;

import java.util.Objects;
import java.util.UUID;

/** Identity value object for {@link DeviceCode}. */
public final class DeviceCodeId {

    private final UUID value;

    private DeviceCodeId(UUID value) {
        this.value = value;
    }

    public static DeviceCodeId generate() {
        return new DeviceCodeId(UUID.randomUUID());
    }

    public static DeviceCodeId of(UUID value) {
        Objects.requireNonNull(value, "DeviceCodeId value must not be null");
        return new DeviceCodeId(value);
    }

    public static DeviceCodeId of(String value) {
        Objects.requireNonNull(value, "DeviceCodeId value must not be null");
        return new DeviceCodeId(UUID.fromString(value));
    }

    public UUID value() {
        return value;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof DeviceCodeId that)) return false;
        return value.equals(that.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
