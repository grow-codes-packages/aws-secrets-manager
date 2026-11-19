package codes.grow.packages.awssecretsmanager;

import codes.grow.packages.awssecretsmanager.core.Json;
import codes.grow.packages.awssecretsmanager.core.MockServer;
import codes.grow.packages.awssecretsmanager.core.RetryPolicy;
import com.fasterxml.jackson.databind.JsonNode;
import com.sun.net.httpserver.HttpExchange;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Queue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

/**
 * AWS JSON 1.1 mock on top of {@link MockServer}: responders are queued per operation ({@code
 * X-Amz-Target}) and the recorded fixtures of {@code fixtures/} are replayed as is.
 */
final class AwsMock implements AutoCloseable {
  static final String SECRET_KEY = "test-secret-access-key-0123456789";

  final MockServer server;
  private final Map<String, Queue<MockServer.Responder>> byOp = new ConcurrentHashMap<>();
  private final Map<String, MockServer.Responder> defaults = new ConcurrentHashMap<>();

  AwsMock() {
    try {
      server = MockServer.start();
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
    server.fallback(this::dispatch);
  }

  private void dispatch(HttpExchange ex) throws Exception {
    String target = ex.getRequestHeaders().getFirst("X-Amz-Target");
    String op = target == null ? "STS" : target.substring(target.indexOf('.') + 1);
    Queue<MockServer.Responder> q = byOp.get(op);
    MockServer.Responder r = q == null ? null : q.poll();
    if (r == null) {
      r = defaults.get(op);
    }
    if (r == null) {
      respond(ex, 400, "{\"__type\":\"UnknownOperationException\",\"message\":\"no mock\"}");
      return;
    }
    r.respond(ex);
  }

  String url() {
    return server.url();
  }

  /** Queues a responder for the next call of {@code op}. */
  AwsMock on(String op, MockServer.Responder r) {
    byOp.computeIfAbsent(op, k -> new ConcurrentLinkedQueue<>()).add(r);
    return this;
  }

  /** Answers every call of {@code op} (after the queue is empty). */
  AwsMock always(String op, MockServer.Responder r) {
    defaults.put(op, r);
    return this;
  }

  /** Queues a JSON answer. */
  AwsMock json(String op, int status, String body, String... headers) {
    return on(
        op,
        ex -> {
          for (int i = 0; i + 1 < headers.length; i += 2) {
            ex.getResponseHeaders().add(headers[i], headers[i + 1]);
          }
          respond(ex, status, body);
        });
  }

  /** Queues an AWS JSON error. */
  AwsMock error(String op, int status, String code) {
    return json(
        op,
        status,
        "{\"__type\":\"" + code + "\",\"message\":\"" + code + " message\"}",
        "x-amzn-RequestId",
        "req-" + code);
  }

  /** Queues the response of a recorded fixture (its operation is read from the file). */
  AwsMock fixture(String name) {
    JsonNode f = load(name);
    return on(f.get("operation").asText(), responder(f));
  }

  static JsonNode load(String name) {
    String path = "fixtures/" + name + ".json";
    try (InputStream in = AwsMock.class.getResourceAsStream(path)) {
      if (in == null) {
        throw new IllegalArgumentException("missing fixture " + name);
      }
      return Json.tree(in.readAllBytes());
    } catch (IOException e) {
      throw new UncheckedIOException(e);
    }
  }

  static MockServer.Responder responder(JsonNode f) {
    JsonNode res = f.get("response");
    return ex -> {
      res.get("headers")
          .properties()
          .forEach(
              h -> {
                String k = h.getKey();
                if (!k.equalsIgnoreCase("content-length") && !k.equalsIgnoreCase("status")) {
                  ex.getResponseHeaders().add(k, h.getValue().asText());
                }
              });
      JsonNode body = res.get("body");
      String text =
          body == null || body.isNull() ? "" : body.isTextual() ? body.asText() : body.toString();
      respond(ex, res.get("status").asInt(), text);
    };
  }

  static void respond(HttpExchange ex, int status, String body) throws IOException {
    byte[] b = body.getBytes(StandardCharsets.UTF_8);
    if (!ex.getResponseHeaders().containsKey("Content-Type")) {
      ex.getResponseHeaders().add("Content-Type", "application/x-amz-json-1.1");
    }
    ex.sendResponseHeaders(status, b.length == 0 ? -1 : b.length);
    if (b.length > 0) {
      try (OutputStream out = ex.getResponseBody()) {
        out.write(b);
      }
    }
  }

  /** Request bodies of {@code op}, in order. */
  List<JsonNode> bodies(String op) {
    List<JsonNode> out = new ArrayList<>();
    for (MockServer.Recorded r : server.requests()) {
      String target = r.header("X-Amz-Target");
      if (target != null && target.endsWith("." + op)) {
        out.add(
            r.body().isEmpty()
                ? Json.mapper().createObjectNode()
                : Json.tree(r.body().getBytes(StandardCharsets.UTF_8)));
      }
    }
    return out;
  }

  /** The last request body of {@code op}. */
  JsonNode last(String op) {
    List<JsonNode> b = bodies(op);
    if (b.isEmpty()) {
      throw new AssertionError("no request for " + op);
    }
    return b.get(b.size() - 1);
  }

  int count(String op) {
    return bodies(op).size();
  }

  /** A builder for a client of this mock (static credentials, region, no retries). */
  AwsSecretsManagerClient.Builder builder() {
    return AwsSecretsManagerClient.builder()
        .url(url())
        .region("us-east-1")
        .credentials("AKIDTESTKEY", SECRET_KEY)
        .retry(RetryPolicy.none());
  }

  AwsSecretsManagerClient client() {
    return builder().build();
  }

  @Override
  public void close() {
    server.close();
  }
}
