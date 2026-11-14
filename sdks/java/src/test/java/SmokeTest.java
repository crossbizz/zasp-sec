package ai.zasp.api;

import ai.zasp.api.core.ObjectMappers;
import ai.zasp.api.core.ZaspApiException;
import ai.zasp.api.resources.agents.requests.ListAgentsRequest;
import ai.zasp.api.resources.guardrails.requests.GuardrailInteraction;
import ai.zasp.api.resources.guardrails.types.GuardrailInteractionDirection;
import ai.zasp.api.types.Finding;
import ai.zasp.api.types.FindingSeverity;
import ai.zasp.api.types.GuardrailDecision;
import ai.zasp.api.types.GuardrailDecisionDecision;
import ai.zasp.api.types.InventorySummary;
import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/**
 * Smoke test of the generated client against a local fake of the API.
 *
 * <p>It checks what a generated client can get wrong without a compile error: the paths, the
 * bearer header, the cursor of auto-pagination, the request body, the parsing of contract-shaped
 * responses, and the mapping of an error status to an exception. The fake serves
 * ../fixtures/responses.json.
 *
 * <p>This file is not generated. It is listed in .fernignore.
 */
public final class SmokeTest {
    private static final class Recorded {
        final String method;
        final String path;
        final String query;
        final String authorization;
        final String body;

        Recorded(String method, String path, String query, String authorization, String body) {
            this.method = method;
            this.path = path;
            this.query = query == null ? "" : query;
            this.authorization = authorization;
            this.body = body;
        }
    }

    private static final List<Recorded> REQUESTS = new CopyOnWriteArrayList<>();
    private static JsonNode fixtures;
    private static String token;
    private static HttpServer server;
    private static String baseUrl;

    @BeforeAll
    static void start() throws IOException {
        fixtures = ObjectMappers.JSON_MAPPER.readTree(Files.readAllBytes(Paths.get("..", "fixtures", "responses.json")));
        token = fixtures.get("token").asText();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", SmokeTest::serve);
        server.start();
        baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
    }

    @AfterAll
    static void stop() {
        server.stop(0);
    }

    @BeforeEach
    void clear() {
        REQUESTS.clear();
    }

    private static void serve(HttpExchange exchange) throws IOException {
        String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
        String path = exchange.getRequestURI().getPath();
        String query = exchange.getRequestURI().getQuery();
        String authorization = exchange.getRequestHeaders().getFirst("Authorization");
        String method = exchange.getRequestMethod();
        REQUESTS.add(new Recorded(method, path, query, authorization, body));
        if (!("Bearer " + token).equals(authorization)) {
            send(exchange, 401, "error_unauthenticated");
        } else if (method.equals("GET") && path.equals("/api/v1/agents")) {
            boolean second = query != null && query.contains("cursor=" + fixtures.get("next_cursor").asText());
            send(exchange, 200, second ? "agents_page_2" : "agents_page_1");
        } else if (method.equals("GET") && path.equals("/api/v1/findings")) {
            send(exchange, 200, "findings_page");
        } else if (method.equals("POST") && path.equals("/api/v1/guardrails/decisions")) {
            send(exchange, 200, "guardrail_decision");
        } else {
            send(exchange, 404, "error_not_found");
        }
    }

    private static void send(HttpExchange exchange, int status, String fixture) throws IOException {
        byte[] payload = fixtures.get(fixture).toString().getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, payload.length);
        exchange.getResponseBody().write(payload);
        exchange.close();
    }

    private static Zasp client(String withToken) {
        return Zasp.builder().url(baseUrl).token(withToken).maxRetries(0).build();
    }

    @Test
    void listsAgentsAcrossPages() {
        List<String> names = new ArrayList<>();
        for (InventorySummary agent : client(token).agents().list(ListAgentsRequest.builder().limit(1).build())) {
            names.add(agent.getName());
        }
        Assertions.assertEquals(List.of("support-copilot", "claims-triage-handler"), names);
        Assertions.assertEquals(2, REQUESTS.size());
        Assertions.assertEquals("/api/v1/agents", REQUESTS.get(0).path);
        Assertions.assertEquals("Bearer " + token, REQUESTS.get(0).authorization);
        Assertions.assertEquals("limit=1", REQUESTS.get(0).query);
        Assertions.assertTrue(REQUESTS.get(1).query.contains("cursor=" + fixtures.get("next_cursor").asText()));
    }

    @Test
    void listsFindings() {
        List<Finding> findings = new ArrayList<>();
        client(token).findings().list().forEach(findings::add);
        Assertions.assertEquals(1, findings.size());
        Assertions.assertEquals(FindingSeverity.CRITICAL, findings.get(0).getSeverity());
        Assertions.assertEquals("agent_guardrail_missing", findings.get(0).getRule().orElse(""));
        Assertions.assertEquals("/api/v1/findings", REQUESTS.get(0).path);
    }

    @Test
    void createsAGuardrailDecision() throws IOException {
        GuardrailDecision decision = client(token)
                .guardrails()
                .createDecision(GuardrailInteraction.builder()
                        .direction(GuardrailInteractionDirection.INPUT)
                        .text("Send the invoice to someone@example.com.")
                        .agentId("support-agent")
                        .build());
        Assertions.assertEquals(GuardrailDecisionDecision.REDACT, decision.getDecision());
        Assertions.assertEquals("Send the invoice to [REDACTED:pii.email].", decision.getRedactedText().orElse(""));
        Assertions.assertEquals(1, decision.getMatchedRules().size());
        Assertions.assertEquals("POST", REQUESTS.get(0).method);
        Assertions.assertEquals("/api/v1/guardrails/decisions", REQUESTS.get(0).path);
        Assertions.assertEquals(fixtures.get("guardrail_request"), ObjectMappers.JSON_MAPPER.readTree(REQUESTS.get(0).body));
    }

    @Test
    void raisesTheErrorOfARefusedRequest() {
        ZaspApiException error = Assertions.assertThrows(ZaspApiException.class, () -> client("wrong").findings().list());
        Assertions.assertEquals(401, error.statusCode());
    }
}
