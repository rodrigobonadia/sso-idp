package com.ssoplatform.idp.api.web.tenant;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.Optional;
import org.junit.jupiter.api.Test;

class TenantSlugExtractorTest {

    @Test
    void extractsTheSlugFromASubdomainOfTheBaseDomain() {
        assertThat(TenantSlugExtractor.extract("acme.localhost", "localhost")).contains("acme");
    }

    @Test
    void isCaseInsensitive() {
        assertThat(TenantSlugExtractor.extract("ACME.LOCALHOST", "localhost")).contains("acme");
    }

    @Test
    void yieldsNoTenantWhenHostIsExactlyTheBaseDomain() {
        assertThat(TenantSlugExtractor.extract("localhost", "localhost")).isEmpty();
    }

    @Test
    void yieldsNoTenantWhenHostIsNotASubdomainOfTheBaseDomainAtAll() {
        assertThat(TenantSlugExtractor.extract("unrelated.example.com", "localhost")).isEmpty();
    }

    @Test
    void yieldsNoTenantForANestedSubdomain() {
        assertThat(TenantSlugExtractor.extract("a.b.localhost", "localhost")).isEmpty();
    }

    @Test
    void worksWithAMultiLabelBaseDomain() {
        assertThat(TenantSlugExtractor.extract("acme.ssoplatform.example", "ssoplatform.example"))
                .contains("acme");
        assertThat(TenantSlugExtractor.extract("ssoplatform.example", "ssoplatform.example"))
                .isEmpty();
    }

    @Test
    void yieldsNoTenantForNullOrBlankInputs() {
        assertThat(TenantSlugExtractor.extract(null, "localhost")).isEmpty();
        assertThat(TenantSlugExtractor.extract("", "localhost")).isEmpty();
        assertThat(TenantSlugExtractor.extract("acme.localhost", null)).isEmpty();
    }

    @Test
    void returnsAnOptionalNotNull() {
        Optional<String> result = TenantSlugExtractor.extract("whatever", "localhost");
        assertThat(result).isNotNull();
    }
}
