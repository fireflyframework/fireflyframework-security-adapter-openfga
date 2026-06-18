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

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import reactor.test.StepVerifier;

import java.util.List;
import java.util.Map;

/**
 * Real integration test of the OpenFGA ReBAC adapter against a live OpenFGA server (Docker).
 * Provisions a store + authorization model, writes a relationship tuple
 * ({@code user:alice} is {@code viewer} of {@code document:budget}), then verifies the adapter's
 * check returns the related subject as allowed and an unrelated subject as denied.
 */
@Testcontainers
class OpenFgaRelationshipAdapterIntegrationTest {

    @Container
    static final GenericContainer<?> OPENFGA = new GenericContainer<>("openfga/openfga:latest")
            .withExposedPorts(8080)
            .withCommand("run")
            .waitingFor(Wait.forHttp("/healthz").forPort(8080).forStatusCode(200));

    static WebClient webClient;
    static String storeId;

    @BeforeAll
    @SuppressWarnings("unchecked")
    static void provisionStore() {
        String baseUrl = "http://" + OPENFGA.getHost() + ":" + OPENFGA.getMappedPort(8080);
        webClient = WebClient.builder().baseUrl(baseUrl).build();

        Map<String, Object> store = webClient.post().uri("/stores")
                .bodyValue(Map.of("name", "firefly"))
                .retrieve().bodyToMono(Map.class).block();
        storeId = (String) store.get("id");

        Map<String, Object> model = Map.of(
                "schema_version", "1.1",
                "type_definitions", List.of(
                        Map.of("type", "user"),
                        Map.of("type", "document",
                                "relations", Map.of("viewer", Map.of("this", Map.of())),
                                "metadata", Map.of("relations", Map.of("viewer",
                                        Map.of("directly_related_user_types", List.of(Map.of("type", "user"))))))));
        webClient.post().uri("/stores/{s}/authorization-models", storeId)
                .bodyValue(model).retrieve().bodyToMono(Map.class).block();

        Map<String, Object> write = Map.of("writes", Map.of("tuple_keys",
                List.of(Map.of("user", "user:alice", "relation", "viewer", "object", "document:budget"))));
        webClient.post().uri("/stores/{s}/write", storeId)
                .bodyValue(write).retrieve().bodyToMono(Map.class).block();
    }

    @Test
    void allowsRelatedSubject() {
        OpenFgaRelationshipAdapter adapter = new OpenFgaRelationshipAdapter(webClient, storeId);
        StepVerifier.create(adapter.check("user:alice", "viewer", "document:budget"))
                .expectNext(true).verifyComplete();
    }

    @Test
    void deniesUnrelatedSubject() {
        OpenFgaRelationshipAdapter adapter = new OpenFgaRelationshipAdapter(webClient, storeId);
        StepVerifier.create(adapter.check("user:bob", "viewer", "document:budget"))
                .expectNext(false).verifyComplete();
    }
}
