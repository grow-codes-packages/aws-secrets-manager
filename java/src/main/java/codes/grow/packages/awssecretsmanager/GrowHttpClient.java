package codes.grow.packages.awssecretsmanager;

import codes.grow.packages.awssecretsmanager.core.ConfigException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InterruptedIOException;
import java.net.Authenticator;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.ProxySelector;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import software.amazon.awssdk.http.AbortableInputStream;
import software.amazon.awssdk.http.ExecutableHttpRequest;
import software.amazon.awssdk.http.HttpExecuteRequest;
import software.amazon.awssdk.http.HttpExecuteResponse;
import software.amazon.awssdk.http.SdkHttpClient;
import software.amazon.awssdk.http.SdkHttpRequest;
import software.amazon.awssdk.http.SdkHttpResponse;

/**
 * The AWS SDK HTTP client of the package: {@code java.net.http.HttpClient} configured from the Grow
 * settings (connect and request timeout, TLS from {@link
 * codes.grow.packages.awssecretsmanager.core.TlsOptions}, explicit proxy with optional credentials,
 * never environment proxies). HTTP/1.1 only, no redirects.
 */
final class GrowHttpClient implements SdkHttpClient {
  /** Headers {@code java.net.http} sets itself and refuses from callers. */
  private static final Set<String> RESTRICTED =
      Set.of("connection", "content-length", "expect", "host", "upgrade");

  private final HttpClient client;
  private final Duration requestTimeout;

  private GrowHttpClient(HttpClient client, Duration requestTimeout) {
    this.client = client;
    this.requestTimeout = requestTimeout;
  }

  /**
   * Builds the JDK client from the configuration.
   *
   * @param config configuration
   * @return the client
   */
  static HttpClient jdkClient(AwsSecretsManagerConfig config) {
    HttpClient.Builder b =
        HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_1_1)
            .connectTimeout(config.connectTimeout())
            .followRedirects(HttpClient.Redirect.NEVER);
    if (config.tls().isCustom()) {
      b.sslContext(config.tls().sslContext());
      if (config.tls().insecureSkipVerify()) {
        config
            .logger()
            .warn(
                "TLS verification is disabled (insecureSkipVerify); never use this in production");
      }
    }
    Optional<String> proxy = config.proxy();
    if (proxy.isPresent()) {
      URI p = parse(proxy.get());
      int port = p.getPort() > 0 ? p.getPort() : ("https".equals(p.getScheme()) ? 443 : 80);
      b.proxy(ProxySelector.of(InetSocketAddress.createUnresolved(p.getHost(), port)));
      String userInfo = p.getRawUserInfo();
      if (userInfo != null) {
        int colon = userInfo.indexOf(':');
        String user =
            URLDecoder.decode(
                colon < 0 ? userInfo : userInfo.substring(0, colon), StandardCharsets.UTF_8);
        char[] pass =
            colon < 0
                ? new char[0]
                : URLDecoder.decode(userInfo.substring(colon + 1), StandardCharsets.UTF_8)
                    .toCharArray();
        b.authenticator(new ProxyAuthenticator(user, pass));
      }
    } else {
      b.proxy(HttpClient.Builder.NO_PROXY);
    }
    return b.build();
  }

  private static URI parse(String proxy) {
    try {
      return new URI(proxy);
    } catch (URISyntaxException e) {
      throw new ConfigException("config: proxy is not a valid URL", e);
    }
  }

  /**
   * Creates an SDK HTTP client on a JDK client.
   *
   * @param client JDK client (shared, never closed here)
   * @param requestTimeout per-attempt timeout until the response headers arrive
   * @return the SDK HTTP client
   */
  static GrowHttpClient of(HttpClient client, Duration requestTimeout) {
    return new GrowHttpClient(client, requestTimeout);
  }

  @Override
  public ExecutableHttpRequest prepareRequest(HttpExecuteRequest request) {
    SdkHttpRequest r = request.httpRequest();
    byte[] body =
        request
            .contentStreamProvider()
            .map(
                p -> {
                  try (InputStream in = p.newStream()) {
                    return in.readAllBytes();
                  } catch (IOException e) {
                    throw new IllegalStateException("cannot read the request body", e);
                  }
                })
            .orElse(new byte[0]);
    HttpRequest.Builder b =
        HttpRequest.newBuilder(r.getUri())
            .timeout(requestTimeout)
            .method(
                r.method().name(),
                body.length == 0
                    ? HttpRequest.BodyPublishers.noBody()
                    : HttpRequest.BodyPublishers.ofByteArray(body));
    r.forEachHeader(
        (name, values) -> {
          if (!RESTRICTED.contains(name.toLowerCase(Locale.ROOT))) {
            for (String v : values) {
              b.header(name, v);
            }
          }
        });
    return new Call(b.build());
  }

  @Override
  public String clientName() {
    return "GrowJdkHttp";
  }

  /** The JDK client is shared and released by the garbage collector; nothing to close. */
  @Override
  public void close() {}

  private final class Call implements ExecutableHttpRequest {
    private final HttpRequest request;
    private volatile CompletableFuture<HttpResponse<byte[]>> inflight;

    Call(HttpRequest request) {
      this.request = request;
    }

    @Override
    public HttpExecuteResponse call() throws IOException {
      CompletableFuture<HttpResponse<byte[]>> f =
          client.sendAsync(request, HttpResponse.BodyHandlers.ofByteArray());
      inflight = f;
      HttpResponse<byte[]> res;
      try {
        res = f.get();
      } catch (InterruptedException e) {
        f.cancel(true);
        Thread.currentThread().interrupt();
        throw new InterruptedIOException("request interrupted");
      } catch (ExecutionException e) {
        Throwable cause = e.getCause();
        if (cause instanceof IOException) {
          throw (IOException) cause;
        }
        throw new IOException(cause);
      }
      SdkHttpResponse.Builder out = SdkHttpResponse.builder().statusCode(res.statusCode());
      for (Map.Entry<String, List<String>> h : res.headers().map().entrySet()) {
        if (!h.getKey().startsWith(":")) {
          out.putHeader(h.getKey(), h.getValue());
        }
      }
      return HttpExecuteResponse.builder()
          .response(out.build())
          .responseBody(AbortableInputStream.create(new ByteArrayInputStream(res.body())))
          .build();
    }

    @Override
    public void abort() {
      CompletableFuture<HttpResponse<byte[]>> f = inflight;
      if (f != null) {
        f.cancel(true);
      }
    }
  }

  /** Supplies proxy credentials only for proxy challenges. */
  private static final class ProxyAuthenticator extends Authenticator {
    private final String user;
    private final char[] password;

    ProxyAuthenticator(String user, char[] password) {
      this.user = user;
      this.password = password;
    }

    @Override
    protected PasswordAuthentication getPasswordAuthentication() {
      if (getRequestorType() != RequestorType.PROXY) {
        return null;
      }
      return new PasswordAuthentication(user, password.clone());
    }
  }
}
