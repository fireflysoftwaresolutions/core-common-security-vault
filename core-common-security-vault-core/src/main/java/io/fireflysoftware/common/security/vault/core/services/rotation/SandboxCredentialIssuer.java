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
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

/**
 * Returns no new secret. Automatic rotation then records the credential as not rotated.
 * This adapter does not open a socket.
 * An installer selects {@link HttpCredentialIssuer} with
 * {@code firefly.security.vault.issuer.adapter=live}.
 */
@Component
@ConditionalOnProperty(name = "firefly.security.vault.issuer.adapter", havingValue = "sandbox", matchIfMissing = true)
public final class SandboxCredentialIssuer implements CredentialIssuer {

    @Override
    public Mono<String> issue(Credential credential) {
        return Mono.empty();
    }
}
