package com.ssoplatform.idp.api.web.tenant;

import static org.assertj.core.api.Assertions.assertThat;

import com.ssoplatform.idp.application.usecase.tenant.CreateTenantCommand;
import com.ssoplatform.idp.application.usecase.tenant.CreateTenantUseCase;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.testcontainers.service.connection.ServiceConnection;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

/**
 * Regression test for a class of bug that MockMvc-based tests structurally cannot catch: Spring
 * Test's {@code ServletTestExecutionListener} pre-binds {@code RequestContextHolder} for the
 * whole test thread, which masks a {@code Filter} depending on a {@code @RequestScope} bean being
 * resolvable earlier than a real embedded servlet container would actually make it so (see
 * {@code WebFilterConfiguration}). {@code @SpringBootTest(webEnvironment = RANDOM_PORT)} boots a
 * real embedded Tomcat; a raw socket - rather than any Java HTTP client - sends the request, since
 * {@code RestTemplate}/{@code HttpClient} refuse to send a custom "Host" header (a JDK-restricted
 * header), which is exactly the mechanism needed to simulate a subdomain request like a browser
 * would send.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Testcontainers
class TenantResolutionRealServerIT {

    @Container
    @ServiceConnection
    static final PostgreSQLContainer<?> POSTGRES = new PostgreSQLContainer<>("postgres:16-alpine");

    @Value("${local.server.port}")
    private int port;

    @Autowired
    private CreateTenantUseCase createTenantUseCase;

    @Test
    void resolvingATenantSubdomainThroughTheRealFilterChainDoesNotFailWithScopeNotActive() throws IOException {
        createTenantUseCase.execute(new CreateTenantCommand("Acme Corp", "acme-real-http-it"));

        String statusLine = sendRawHttpGet("/register", "acme-real-http-it.localhost");

        assertThat(statusLine).contains("200");
    }

    private String sendRawHttpGet(String path, String host) throws IOException {
        try (Socket socket = new Socket("localhost", port)) {
            OutputStream out = socket.getOutputStream();
            String request = "GET " + path + " HTTP/1.1\r\n" + "Host: " + host + "\r\nConnection: close\r\n\r\n";
            out.write(request.getBytes(StandardCharsets.US_ASCII));
            out.flush();

            try (BufferedReader reader =
                    new BufferedReader(new InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII))) {
                return reader.readLine();
            }
        }
    }
}
