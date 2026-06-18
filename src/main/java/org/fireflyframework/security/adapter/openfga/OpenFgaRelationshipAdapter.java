/*
 * Copyright 2024-2026 Firefly Software Foundation
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

package org.fireflyframework.security.adapter.openfga;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.fireflyframework.security.spi.RelationshipPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * {@link RelationshipPort} backed by OpenFGA (a Zanzibar-style ReBAC engine). Issues a relationship
 * {@code check} against an OpenFGA store and maps the {@code allowed} flag to a boolean.
 * <strong>Fail-closed</strong>: any transport error denies.
 */
public class OpenFgaRelationshipAdapter implements RelationshipPort {

    private static final Logger log = LoggerFactory.getLogger(OpenFgaRelationshipAdapter.class);

    private final WebClient webClient;
    private final String storeId;

    /**
     * @param webClient a WebClient whose base URL points at the OpenFGA HTTP API
     * @param storeId   the OpenFGA store id to query
     */
    public OpenFgaRelationshipAdapter(WebClient webClient, String storeId) {
        this.webClient = webClient;
        this.storeId = storeId;
    }

    @Override
    public Mono<Boolean> check(String subject, String relation, String object) {
        Map<String, Object> body = Map.of("tuple_key",
                Map.of("user", subject, "relation", relation, "object", object));

        return webClient.post()
                .uri("/stores/{storeId}/check", storeId)
                .bodyValue(body)
                .retrieve()
                .bodyToMono(CheckResult.class)
                .map(result -> Boolean.TRUE.equals(result.allowed()))
                .onErrorResume(error -> {
                    log.warn("OpenFGA check failed; failing closed: {}", error.getMessage());
                    return Mono.just(Boolean.FALSE);
                });
    }

    /** Subset of the OpenFGA check response ({@code {"allowed": <bool>}}). */
    @JsonIgnoreProperties(ignoreUnknown = true)
    record CheckResult(Boolean allowed) {
    }
}
