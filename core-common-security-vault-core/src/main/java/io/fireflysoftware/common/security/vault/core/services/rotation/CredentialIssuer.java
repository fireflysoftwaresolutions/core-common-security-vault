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
import reactor.core.publisher.Mono;

/**
 * Issues a replacement secret for a credential.
 * {@link SandboxCredentialIssuer} is the default and returns no secret.
 * An installer replaces {@link HttpCredentialIssuer} and selects it with
 * {@code firefly.security.vault.issuer.adapter=live}.
 */
public interface CredentialIssuer {

    /**
     * A new secret, or empty when this issuer has no replacement value.
     */
    Mono<String> issue(Credential credential);
}
