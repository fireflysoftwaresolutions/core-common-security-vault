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

import io.fireflysoftware.common.security.vault.models.entities.Credential;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Posts a rotation request to {@code firefly.security.vault.issuer.endpoint}.
 * A textual {@code secret} field in the JSON response is the new value.
 * An installer replaces this class when the issuer protocol is different.
 * Selected only when {@code firefly.security.vault.issuer.adapter=live}.
 */
@Component
@ConditionalOnProperty(name = "firefly.security.vault.issuer.adapter", havingValue = "live")
public final class HttpCredentialIssuer implements CredentialIssuer {

    private final WebClient client;

    @Autowired
    public HttpCredentialIssuer(@Value("${firefly.security.vault.issuer.endpoint:}") String endpoint) {
        this(client(endpoint));
    }

    HttpCredentialIssuer(WebClient client) {
        this.client = client;
    }

    @Override
    public Mono<String> issue(Credential credential) {
        if (credential == null || credential.getId() == null) {
            return Mono.empty();
        }
        Map<String, String> body = new LinkedHashMap<>();
        body.put("credentialId", credential.getId().toString());
        if (credential.getCode() != null && !credential.getCode().isBlank()) {
            body.put("code", credential.getCode());
        }
        return client.post()
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(new ParameterizedTypeReference<Map<String, Object>>() {})
                .flatMap(HttpCredentialIssuer::secret);
    }

    private static Mono<String> secret(Map<String, Object> body) {
        if (body == null) {
            return Mono.empty();
        }
        Object value = body.get("secret");
        if (!(value instanceof String text) || text.isBlank()) {
            return Mono.empty();
        }
        return Mono.just(text);
    }

    private static WebClient client(String endpoint) {
        if (endpoint == null || endpoint.isBlank()) {
            throw new IllegalStateException("firefly.security.vault.issuer.endpoint is not set");
        }
        String base = endpoint.endsWith("/") ? endpoint.substring(0, endpoint.length() - 1) : endpoint;
        return WebClient.builder().baseUrl(base).build();
    }
}
