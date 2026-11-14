# Zasp Java SDK

A Java client for the Zasp API. The sources under `src/main/java` are generated
by Fern from `openapi/openapi.yaml`. It needs Java 11 or later, OkHttp and
Jackson.

Every method is listed in [reference.md](reference.md).

This README, `pom.xml` and `src/test/java/SmokeTest.java` are not generated.
They are listed in `.fernignore`, so generating the SDK again keeps them.

The generator writes the sources without package directories: `Zasp.java` is in
`src/main/java` and declares the package `ai.zasp.api`. The compiler accepts
that; some editors show a warning.

## Install from source

The artifact is not published. Install it into your local Maven repository:

```bash
cd sdks/java
```

```bash
mvn -B -DskipTests install
```

Then depend on it:

```xml
<dependency>
  <groupId>ai.zasp</groupId>
  <artifactId>zasp-api</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Use

```java
import ai.zasp.api.Zasp;
import ai.zasp.api.core.ZaspApiException;
import ai.zasp.api.resources.agents.requests.ListAgentsRequest;
import ai.zasp.api.resources.guardrails.requests.GuardrailInteraction;
import ai.zasp.api.resources.guardrails.types.GuardrailInteractionDirection;
import ai.zasp.api.types.Finding;
import ai.zasp.api.types.GuardrailDecision;
import ai.zasp.api.types.GuardrailDecisionDecision;
import ai.zasp.api.types.InventorySummary;

public final class Example {
    public static void main(String[] args) {
        Zasp client = Zasp.builder()
                .url("https://zasp.example.com")
                .token(System.getenv("ZASP_API_TOKEN"))
                .build();

        // List agents. The iterable requests the next page when a page is used up.
        for (InventorySummary agent : client.agents().list(ListAgentsRequest.builder().limit(50).build())) {
            System.out.println(agent.getName() + " " + agent.getManagementState());
        }

        // List findings.
        for (Finding finding : client.findings().list()) {
            System.out.println(finding.getSeverity() + " " + finding.getTitle());
        }

        // Ask for a guardrail decision. The token needs the decide_guardrails permission.
        try {
            GuardrailDecision decision = client.guardrails().createDecision(GuardrailInteraction.builder()
                    .direction(GuardrailInteractionDirection.INPUT)
                    .text("Send the invoice to someone@example.com.")
                    .agentId("support-agent")
                    .build());
            if (decision.getDecision().equals(GuardrailDecisionDecision.BLOCK)) {
                throw new IllegalStateException("Blocked by guardrail");
            }
            String text = decision.getRedactedText().orElse("the original text");
            System.out.println(text);
        } catch (ZaspApiException error) {
            // A refused request carries the status and the product error.
            System.err.println(error.statusCode() + " " + error.body());
        }
    }
}
```

## Test

```bash
cd sdks/java
```

```bash
mvn -B test
```

The smoke test starts a local fake of the API and checks the requests the
client sends. It needs no network and no token. Maven downloads the
dependencies from Maven Central the first time.
