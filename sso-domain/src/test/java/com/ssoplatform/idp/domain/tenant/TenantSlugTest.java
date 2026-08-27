package com.ssoplatform.idp.domain.tenant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;

class TenantSlugTest {

    @Test
    void normalizesCasing() {
        assertThat(TenantSlug.of("Acme-Corp").value()).isEqualTo("acme-corp");
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(
            strings = {
                " ",
                "1starts-with-digit",
                "-starts-with-hyphen",
                "has spaces",
                "has_underscore",
                "has.dot",
                "a" // single character: too short to satisfy the pattern
            })
    void rejectsInvalidSlugs(String invalid) {
        assertThatThrownBy(() -> TenantSlug.of(invalid)).isInstanceOf(InvalidTenantSlugException.class);
    }

    @Test
    void rejectsSlugsLongerThanSixtyThreeCharacters() {
        String tooLong = "a".repeat(64);

        assertThatThrownBy(() -> TenantSlug.of(tooLong)).isInstanceOf(InvalidTenantSlugException.class);
    }

    @Test
    void twoEqualSlugsAreEqual() {
        assertThat(TenantSlug.of("acme")).isEqualTo(TenantSlug.of("ACME"));
    }
}
