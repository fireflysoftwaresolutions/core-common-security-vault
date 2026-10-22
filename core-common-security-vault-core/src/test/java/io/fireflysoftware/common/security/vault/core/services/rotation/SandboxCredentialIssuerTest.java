/*
 * Copyright 2026 Firefly Software Foundation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


package io.fireflysoftware.common.security.vault.core.services.rotation;

import io.fireflysoftware.common.security.vault.core.config.SecurityVaultProperties;
import io.fireflysoftware.common.security.vault.core.services.audit.CredentialAuditService;
import io.fireflysoftware.common.security.vault.core.services.encryption.EncryptionService;
import io.fireflysoftware.common.security.vault.models.entities.Credential;
import io.fireflysoftware.common.security.vault.models.repositories.CredentialRepository;
import io.fireflysoftware.common.security.vault.models.repositories.CredentialVersionRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SandboxCredentialIssuerTest {

    @Mock
    private CredentialRepository credentialRepository;

    @Mock
    private CredentialVersionRepository credentialVersionRepository;

    @Mock
    private EncryptionService encryptionService;

    @Mock
    private CredentialAuditService auditService;

    private CredentialRotationService service;
    private Credential credential;

    @BeforeEach
    void setUp() {
        service = new CredentialRotationService(
                credentialRepository,
                credentialVersionRepository,
                encryptionService,
                auditService,
                new SecurityVaultProperties(),
                new SandboxCredentialIssuer());
        credential = Credential.builder()
                .id(UUID.fromString("22222222-2222-4222-8222-222222222222"))
                .code("db-password")
                .rotationEnabled(true)
                .expiresAt(LocalDateTime.now().minusDays(1))
                .encryptedValue("cipher")
                .encryptionKeyId("key-1")
                .build();
    }

    @Test
    void sandboxIssuerDoesNotMarkTheCredentialRotated() {
        when(credentialRepository.findAll()).thenReturn(Flux.just(credential));
        when(auditService.logCredentialNotRotated(eq(credential.getId()), any())).thenReturn(Mono.empty());

        StepVerifier.create(new SandboxCredentialIssuer().issue(credential))
                .expectComplete()
                .verify(Duration.ofSeconds(2));

        StepVerifier.create(service.rotateAutomatic(credential))
                .assertNext(result -> {
                    assertThat(result.success()).isFalse();
                    assertThat(result.message()).isEqualTo("Credential was not rotated");
                })
                .verifyComplete();

        StepVerifier.create(service.rotateExpiredCredentials())
                .expectNext(0L)
                .verifyComplete();

        assertThat(credential.getLastRotatedAt()).isNull();
        verify(credentialRepository, never()).save(any());
        verify(encryptionService, never()).encrypt(any(), any());
        verify(auditService, never()).logCredentialRotation(any(), any(), any());
        verify(auditService, org.mockito.Mockito.atLeastOnce())
                .logCredentialNotRotated(eq(credential.getId()), eq("Issuer returned no new secret"));
    }

    @Test
    void liveIssuerReadsTheConfiguredEndpoint() {
        AtomicReference<String> seen = new AtomicReference<>();
        WebClient client = WebClient.builder()
                .baseUrl("http://issuer.internal/rotate")
                .exchangeFunction(request -> {
                    seen.set(request.url().toString());
                    return Mono.just(ClientResponse.create(HttpStatus.OK)
                            .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                            .body("{\"secret\":\"next-secret\"}")
                            .build());
                })
                .build();

        StepVerifier.create(new HttpCredentialIssuer(client).issue(credential))
                .expectNext("next-secret")
                .verifyComplete();
        assertThat(seen.get()).isEqualTo("http://issuer.internal/rotate");

        WebClient emptySecret = WebClient.builder()
                .baseUrl("http://issuer.internal/rotate")
                .exchangeFunction(request -> Mono.just(ClientResponse.create(HttpStatus.OK)
                        .header(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .body("{\"secret\":\"\"}")
                        .build()))
                .build();
        StepVerifier.create(new HttpCredentialIssuer(emptySecret).issue(credential))
                .expectComplete()
                .verify(Duration.ofSeconds(2));

        assertThatThrownBy(() -> new HttpCredentialIssuer(" "))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("issuer.endpoint");
    }
}
