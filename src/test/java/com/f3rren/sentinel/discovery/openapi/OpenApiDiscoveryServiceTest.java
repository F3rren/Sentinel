package com.f3rren.sentinel.discovery.openapi;

import com.f3rren.sentinel.http.HttpResponseData;
import com.f3rren.sentinel.http.SentinelHttpClient;
import com.f3rren.sentinel.model.Endpoint;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpMethod;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.ObjectMapper;

import java.time.Instant;
import java.time.LocalDate;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class OpenApiDiscoveryServiceTest {

    private static final String SPEC = """
            {
              "openapi": "3.0.1",
              "paths": {
                "/api/search": {
                  "get": {
                    "parameters": [
                      {"name": "q", "in": "query", "schema": {"type": "string"}},
                      {"name": "page", "in": "query", "schema": {"type": "integer"}}
                    ]
                  }
                },
                "/api/users/{id}": {
                  "get": {
                    "parameters": [
                      {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}
                    ]
                  },
                  "delete": {
                    "parameters": [
                      {"name": "id", "in": "path", "required": true, "schema": {"type": "integer"}}
                    ]
                  }
                },
                "/api/orders": {
                  "post": {
                    "parameters": [
                      {"name": "customerId", "in": "query", "schema": {"type": "string"}}
                    ]
                  }
                },
                "/api/broken/{missing}": {
                  "get": {}
                }
              }
            }
            """;

    private static final String SWAGGER_CONFIG = """
            {
              "urls": [
                {"url": "/aquariums-service/v3/api-docs", "name": "aquariums-service"},
                {"url": "/species-service/v3/api-docs", "name": "species-service"}
              ]
            }
            """;

    private static final String SWAGGER_RESOURCES = """
            [
              {"name": "aquariums-service", "url": "/aquariums-service/v2/api-docs", "swaggerVersion": "2.0"}
            ]
            """;

    private static final String SERVICE_A_SPEC = """
            {
              "openapi": "3.0.1",
              "paths": {
                "/aquariums": {
                  "get": {
                    "parameters": [
                      {"name": "name", "in": "query", "schema": {"type": "string"}}
                    ]
                  }
                }
              }
            }
            """;

    private static final String SERVICE_B_SPEC = """
            {
              "openapi": "3.0.1",
              "paths": {
                "/species": {
                  "post": {
                    "parameters": [
                      {"name": "search", "in": "query", "schema": {"type": "string"}}
                    ]
                  }
                }
              }
            }
            """;

    private static final String SPEC_WITH_REQUEST_BODY = """
            {
              "openapi": "3.0.1",
              "paths": {
                "/aquariums": {
                  "post": {
                    "requestBody": {
                      "content": {
                        "application/json": {
                          "schema": { "$ref": "#/components/schemas/CreateAquariumDTO" }
                        }
                      }
                    }
                  }
                },
                "/no-body": {
                  "post": {}
                }
              },
              "components": {
                "schemas": {
                  "CreateAquariumDTO": {
                    "type": "object",
                    "properties": {
                      "name": {"type": "string"},
                      "volume": {"type": "integer"},
                      "saltwater": {"type": "boolean"},
                      "type": { "$ref": "#/components/schemas/AquariumType" }
                    }
                  },
                  "AquariumType": {
                    "type": "string",
                    "enum": ["FRESHWATER", "SALTWATER"]
                  }
                }
              }
            }
            """;

    private static final String SPEC_WITH_DATE_FIELDS = """
            {
              "openapi": "3.0.1",
              "paths": {
                "/products": {
                  "post": {
                    "requestBody": {
                      "content": {
                        "application/json": {
                          "schema": { "$ref": "#/components/schemas/CreateProductDTO" }
                        }
                      }
                    }
                  }
                }
              },
              "components": {
                "schemas": {
                  "CreateProductDTO": {
                    "required": ["name"],
                    "type": "object",
                    "properties": {
                      "name": {"type": "string"},
                      "purchaseDate": {"type": "string", "format": "date"},
                      "recordedAt": {"type": "string", "format": "date-time"}
                    }
                  }
                }
              }
            }
            """;

    private static final String SPEC_WITH_OPTIONAL_PATTERN_FIELD = """
            {
              "openapi": "3.0.1",
              "paths": {
                "/aquariums": {
                  "post": {
                    "requestBody": {
                      "content": {
                        "application/json": {
                          "schema": { "$ref": "#/components/schemas/CreateAquariumDTO" }
                        }
                      }
                    }
                  }
                }
              },
              "components": {
                "schemas": {
                  "CreateAquariumDTO": {
                    "required": ["name", "type"],
                    "type": "object",
                    "properties": {
                      "name": {"type": "string", "minLength": 2, "maxLength": 100},
                      "type": {"type": "string", "enum": ["saltwater", "freshwater"]},
                      "volume": {"type": "integer", "maximum": 100000},
                      "imageUrl": {
                        "type": "string",
                        "pattern": "^$|^https?://[^\\\\s/$.?#].[^\\\\s]*$"
                      },
                      "tags": {"type": "array", "items": {"type": "string"}},
                      "metadata": {"type": "object"}
                    }
                  }
                }
              }
            }
            """;

    @Mock
    private SentinelHttpClient httpClient;

    @Test
    void extractsEndpointsFromOpenApiSpec() throws Exception {
        when(httpClient.get(anyString())).thenAnswer(invocation -> {
            String url = invocation.getArgument(0);
            if (url.endsWith("/v3/api-docs")) {
                return new HttpResponseData(200, SPEC, 5);
            }
            return new HttpResponseData(404, "", 5);
        });

        OpenApiDiscoveryService service = new OpenApiDiscoveryService(httpClient);
        Optional<OpenApiDiscoveryResult> result = service.discover("http://localhost:8080");

        assertThat(result).isPresent();
        assertThat(result.get().specUrl()).isEqualTo("http://localhost:8080/v3/api-docs");

        List<Endpoint> endpoints = result.get().endpoints();
        assertThat(endpoints).hasSize(4);

        Endpoint search = find(endpoints, HttpMethod.GET, "http://localhost:8080/api/search");
        assertThat(search.params()).extracting("name").containsExactlyInAnyOrder("q", "page");

        Endpoint getUser = find(endpoints, HttpMethod.GET, "http://localhost:8080/api/users/1");
        assertThat(getUser.params()).isEmpty();

        Endpoint deleteUser = find(endpoints, HttpMethod.DELETE, "http://localhost:8080/api/users/1");
        assertThat(deleteUser.params()).isEmpty();

        Endpoint orders = find(endpoints, HttpMethod.POST, "http://localhost:8080/api/orders");
        assertThat(orders.params()).extracting("name").containsExactly("customerId");

        assertThat(endpoints).noneMatch(e -> e.url().contains("{"));
    }

    @Test
    void returnsEmptyWhenNoSpecIsFound() throws Exception {
        when(httpClient.get(anyString())).thenReturn(new HttpResponseData(404, "", 5));

        OpenApiDiscoveryService service = new OpenApiDiscoveryService(httpClient);

        assertThat(service.discover("http://localhost:8080")).isEmpty();
    }

    @Test
    void discoversEndpointsThroughAggregatedSpringdocSwaggerConfig() throws Exception {
        when(httpClient.get(anyString())).thenAnswer(invocation -> {
            String url = invocation.getArgument(0);
            return switch (url) {
                case "http://localhost:8080/v3/api-docs/swagger-config" -> new HttpResponseData(200, SWAGGER_CONFIG, 5);
                case "http://localhost:8080/aquariums-service/v3/api-docs" -> new HttpResponseData(200, SERVICE_A_SPEC, 5);
                case "http://localhost:8080/species-service/v3/api-docs" -> new HttpResponseData(200, SERVICE_B_SPEC, 5);
                default -> new HttpResponseData(404, "", 5);
            };
        });

        OpenApiDiscoveryService service = new OpenApiDiscoveryService(httpClient);
        Optional<OpenApiDiscoveryResult> result = service.discover("http://localhost:8080");

        assertThat(result).isPresent();
        assertThat(result.get().specUrl()).isEqualTo("http://localhost:8080/v3/api-docs/swagger-config");

        List<Endpoint> endpoints = result.get().endpoints();
        assertThat(endpoints).hasSize(2);

        Endpoint aquariums = find(endpoints, HttpMethod.GET, "http://localhost:8080/aquariums");
        assertThat(aquariums.params()).extracting("name").containsExactly("name");

        Endpoint species = find(endpoints, HttpMethod.POST, "http://localhost:8080/species");
        assertThat(species.params()).extracting("name").containsExactly("search");
    }

    @Test
    void discoversEndpointsThroughSpringfoxSwaggerResourcesArray() throws Exception {
        when(httpClient.get(anyString())).thenAnswer(invocation -> {
            String url = invocation.getArgument(0);
            return switch (url) {
                case "http://localhost:8080/swagger-resources" -> new HttpResponseData(200, SWAGGER_RESOURCES, 5);
                case "http://localhost:8080/aquariums-service/v2/api-docs" -> new HttpResponseData(200, SERVICE_A_SPEC, 5);
                default -> new HttpResponseData(404, "", 5);
            };
        });

        OpenApiDiscoveryService service = new OpenApiDiscoveryService(httpClient);
        Optional<OpenApiDiscoveryResult> result = service.discover("http://localhost:8080");

        assertThat(result).isPresent();
        assertThat(result.get().specUrl()).isEqualTo("http://localhost:8080/swagger-resources");
        assertThat(result.get().endpoints()).hasSize(1);
        assertThat(result.get().endpoints().get(0).url()).isEqualTo("http://localhost:8080/aquariums");
    }

    @Test
    void generatesTypedJsonRequestBodyFromReferencedSchema() throws Exception {
        when(httpClient.get(anyString())).thenAnswer(invocation -> {
            String url = invocation.getArgument(0);
            if (url.endsWith("/v3/api-docs")) {
                return new HttpResponseData(200, SPEC_WITH_REQUEST_BODY, 5);
            }
            return new HttpResponseData(404, "", 5);
        });

        OpenApiDiscoveryService service = new OpenApiDiscoveryService(httpClient);
        Optional<OpenApiDiscoveryResult> result = service.discover("http://localhost:8080");

        assertThat(result).isPresent();
        List<Endpoint> endpoints = result.get().endpoints();

        Endpoint createAquarium = find(endpoints, HttpMethod.POST, "http://localhost:8080/aquariums");
        assertThat(createAquarium.requestBodySample()).isNotNull();

        JsonNode body = new ObjectMapper().readTree(createAquarium.requestBodySample());
        assertThat(body.path("name").isTextual()).isTrue();
        assertThat(body.path("volume").isInt()).isTrue();
        assertThat(body.path("volume").asInt()).isEqualTo(1);
        assertThat(body.path("saltwater").isBoolean()).isTrue();
        assertThat(body.path("saltwater").asBoolean()).isTrue();
        // "type" is a $ref to a separate enum schema, not inlined on the property itself: it
        // must resolve to a real enum constant, not the generic "test" string fallback that
        // would fail Jackson's enum deserialization before validation even runs.
        assertThat(body.path("type").asText()).isEqualTo("FRESHWATER");

        Endpoint noBody = find(endpoints, HttpMethod.POST, "http://localhost:8080/no-body");
        assertThat(noBody.requestBodySample()).isNull();
    }

    @Test
    void generatesCurrentDateAndDateTimeValuesInsteadOfAStaleFixedLiteral() throws Exception {
        when(httpClient.get(anyString())).thenAnswer(invocation -> {
            String url = invocation.getArgument(0);
            if (url.endsWith("/v3/api-docs")) {
                return new HttpResponseData(200, SPEC_WITH_DATE_FIELDS, 5);
            }
            return new HttpResponseData(404, "", 5);
        });

        OpenApiDiscoveryService service = new OpenApiDiscoveryService(httpClient);
        Optional<OpenApiDiscoveryResult> result = service.discover("http://localhost:8080");

        assertThat(result).isPresent();
        Endpoint createProduct = find(result.get().endpoints(), HttpMethod.POST, "http://localhost:8080/products");
        JsonNode body = new ObjectMapper().readTree(createProduct.requestBodySample());

        // A hardcoded past literal (e.g. "2024-01-01") only gets staler as real time passes and
        // is guaranteed to eventually violate any "not in the past" / recency validation. "Now"
        // has no such expiry.
        assertThat(LocalDate.parse(body.path("purchaseDate").asText())).isEqualTo(LocalDate.now());
        assertThat(Instant.parse(body.path("recordedAt").asText()))
                .isCloseTo(Instant.now(), org.assertj.core.api.Assertions.within(java.time.Duration.ofMinutes(1)));
    }

    @Test
    void populatesOptionalPropertiesExceptThoseWithAPatternConstraint() throws Exception {
        when(httpClient.get(anyString())).thenAnswer(invocation -> {
            String url = invocation.getArgument(0);
            if (url.endsWith("/v3/api-docs")) {
                return new HttpResponseData(200, SPEC_WITH_OPTIONAL_PATTERN_FIELD, 5);
            }
            return new HttpResponseData(404, "", 5);
        });

        OpenApiDiscoveryService service = new OpenApiDiscoveryService(httpClient);
        Optional<OpenApiDiscoveryResult> result = service.discover("http://localhost:8080");

        assertThat(result).isPresent();
        Endpoint createAquarium = find(result.get().endpoints(), HttpMethod.POST, "http://localhost:8080/aquariums");
        assertThat(createAquarium.requestBodySample()).isNotNull();

        JsonNode body = new ObjectMapper().readTree(createAquarium.requestBodySample());
        // name and type are required: must be present.
        assertThat(body.has("name")).isTrue();
        assertThat(body.path("type").asText()).isEqualTo("saltwater");
        // volume is optional but has no pattern to violate - a Java primitive int field backing
        // it would otherwise deserialize to 0 when the property is absent, which can fail its
        // own validation (e.g. @Positive) independently of anything auth-related. Sending a real
        // value avoids that trap.
        assertThat(body.path("volume").isInt()).isTrue();
        assertThat(body.path("volume").asInt()).isEqualTo(1);
        // imageUrl is optional and guarded by a URL pattern our generic sample can't satisfy -
        // omitting it (leaving it null/absent) passes validation; a "test" placeholder wouldn't.
        assertThat(body.has("imageUrl")).isFalse();
        // tags/metadata are optional array/object properties: an empty [] or {} would still be a
        // non-null value, so a @Size(min=1) or a cascaded @Valid on a nested DTO could reject it
        // where an absent field would have been skipped entirely. Omit them too.
        assertThat(body.has("tags")).isFalse();
        assertThat(body.has("metadata")).isFalse();
    }

    private Endpoint find(List<Endpoint> endpoints, HttpMethod method, String url) {
        return endpoints.stream()
                .filter(e -> e.method() == method && e.url().equals(url))
                .findFirst()
                .orElseThrow(() -> new AssertionError("No endpoint found for " + method + " " + url));
    }
}
