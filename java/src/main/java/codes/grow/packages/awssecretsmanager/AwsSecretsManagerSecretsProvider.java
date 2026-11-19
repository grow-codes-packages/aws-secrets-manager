package codes.grow.packages.awssecretsmanager;

import codes.grow.packages.awssecretsmanager.core.AwsSecretsManagerException;
import codes.grow.packages.awssecretsmanager.core.ErrorCode;
import codes.grow.packages.awssecretsmanager.core.NotFoundException;
import codes.grow.packages.awssecretsmanager.core.ValidationException;
import codes.grow.packages.awssecretsmanager.secrets.BaseSecretsProvider;
import codes.grow.packages.awssecretsmanager.secrets.DeleteOptions;
import codes.grow.packages.awssecretsmanager.secrets.GetOptions;
import codes.grow.packages.awssecretsmanager.secrets.SecretMetadata;
import codes.grow.packages.awssecretsmanager.secrets.SecretValue;
import codes.grow.packages.awssecretsmanager.secrets.SetOptions;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * {@code SecretsProvider} (SPEC section 3) over AWS Secrets Manager. Capabilities: {@code write},
 * {@code versions}, {@code delete}.
 *
 * <ul>
 *   <li>Names are flat AWS secret names that may contain {@code /}: {@code path + "/" + name} when
 *       a path is given.
 *   <li>{@code get(name, version)} reads {@code VersionId = version} (stage labels: use {@link
 *       AwsSecretsManagerClient#getSecretValue(String, GetSecretValueOptions)}). A secret scheduled
 *       for deletion counts as missing.
 *   <li>{@code set} stores UTF-8 text as {@code SecretString} and other bytes as {@code
 *       SecretBinary}; it creates the secret when missing (with description and tags) and returns
 *       the new version id. {@code cas} is not supported ({@link ValidationException}).
 *   <li>{@code delete} schedules deletion with the recovery window (default 30 days); {@code
 *       permanent} deletes immediately. A name scheduled for deletion cannot be written again until
 *       it is restored or purged.
 *   <li>{@code list(prefix)} matches names by string prefix (recursive); {@code getAll(path)}
 *       returns the secrets directly under {@code path} (non-recursive).
 * </ul>
 */
public final class AwsSecretsManagerSecretsProvider extends BaseSecretsProvider {
  /** Capabilities declared to the conformance runner. */
  public static final List<String> CAPABILITIES = List.of("write", "versions", "delete");

  /** Batch error codes that mean "missing" for {@code getMany} (deleted counts as missing). */
  private static final Set<String> MISSING_BATCH_CODES =
      Set.of("ResourceNotFoundException", "InvalidRequestException");

  private final AwsSecretsManagerClient client;
  private final int recoveryWindowDays;
  private final Runnable onClose;

  AwsSecretsManagerSecretsProvider(
      AwsSecretsManagerClient client, AwsSecretsManagerSecretsOptions options, Runnable onClose) {
    this.client = Objects.requireNonNull(client, "client");
    int days =
        options.recoveryWindowDays() != null
            ? options.recoveryWindowDays()
            : client.config().recoveryWindowDays();
    if (days < 7 || days > 30) {
      throw new ValidationException("secrets: recoveryWindowDays must be an integer from 7 to 30");
    }
    this.recoveryWindowDays = days;
    this.onClose = onClose;
  }

  /**
   * Returns the client this provider uses.
   *
   * @return the client
   */
  public AwsSecretsManagerClient client() {
    return client;
  }

  /**
   * Returns the recovery window of {@code delete()} in days.
   *
   * @return the window
   */
  public int recoveryWindowDays() {
    return recoveryWindowDays;
  }

  /**
   * Returns {@code path/name} when a path is given, otherwise {@code name}.
   *
   * @param name secret name
   * @param path folder, may be null
   * @return the full name
   */
  public static String fullName(String name, String path) {
    String p = path == null ? "" : trimSlashes(path);
    return p.isEmpty() ? name : p + "/" + name;
  }

  private static String trimSlashes(String path) {
    int start = 0;
    int end = path.length();
    while (start < end && path.charAt(start) == '/') {
      start++;
    }
    while (end > start && path.charAt(end - 1) == '/') {
      end--;
    }
    return path.substring(start, end);
  }

  /** Not found, or {@code InvalidRequestException} for a secret scheduled for deletion. */
  static boolean isMissing(AwsSecretsManagerException e) {
    return e.code() == ErrorCode.NOT_FOUND
        || (e.code() == ErrorCode.CONFLICT
            && AwsErrors.awsErrorCode(e).filter("InvalidRequestException"::equals).isPresent());
  }

  /**
   * Converts a description into SPEC metadata.
   *
   * @param d the description
   * @return the metadata
   */
  public static SecretMetadata toMetadata(SecretDescription d) {
    SecretMetadata.Builder b =
        SecretMetadata.builder(d.name())
            .tags(d.tags())
            .versions(d.versionIdsToStages().size())
            .extra("arn", d.arn())
            .extra("rotationEnabled", String.valueOf(d.rotationEnabled()));
    int slash = d.name().lastIndexOf('/');
    if (slash > 0) {
      b.path(d.name().substring(0, slash));
    }
    d.currentVersionId().ifPresent(b::version);
    if (d.createdDate() != null) {
      b.createdAt(d.createdDate());
    }
    if (d.lastChangedDate() != null) {
      b.updatedAt(d.lastChangedDate());
    }
    if (d.description() != null) {
      b.extra("description", d.description());
    }
    if (d.kmsKeyId() != null) {
      b.extra("kmsKeyId", d.kmsKeyId());
    }
    if (d.nextRotationDate() != null) {
      b.extra("nextRotationDate", d.nextRotationDate().toString());
    }
    if (d.deletedDate() != null) {
      b.extra("deletedDate", d.deletedDate().toString());
    }
    if (d.primaryRegion() != null) {
      b.extra("primaryRegion", d.primaryRegion());
    }
    return b.build();
  }

  @Override
  protected Optional<SecretValue> fetchSecret(String name, GetOptions opts) {
    try {
      GetSecretValueOptions o = new GetSecretValueOptions(opts.version().orElse(null), null);
      return Optional.of(
          client.getSecretValue(fullName(name, opts.path().orElse(null)), o).value());
    } catch (AwsSecretsManagerException e) {
      if (isMissing(e)) {
        return Optional.empty();
      }
      throw e;
    }
  }

  @Override
  protected List<SecretMetadata> listSecrets(String path) {
    List<SecretMetadata> out = new ArrayList<>();
    for (SecretDescription d : listDescriptions(path)) {
      out.add(toMetadata(d));
    }
    return out;
  }

  /** Live secrets whose name starts with {@code prefix} (AWS also matches word prefixes). */
  private List<SecretDescription> listDescriptions(String prefix) {
    ListSecretsOptions.Builder o = ListSecretsOptions.builder();
    if (!prefix.isEmpty()) {
      o.filters(List.of(SecretFilter.name(prefix)));
    }
    List<SecretDescription> out = new ArrayList<>();
    for (SecretDescription d : client.listSecrets(o.build())) {
      if (d.name().startsWith(prefix) && !d.pendingDeletion()) {
        out.add(d);
      }
    }
    return out;
  }

  /**
   * Returns every secret directly under {@code path} (non-recursive), keyed by full name, read with
   * {@code BatchGetSecretValue}.
   */
  @Override
  public Map<String, SecretValue> getAll(String path) {
    String base = path == null ? "" : trimSlashes(path);
    String prefix = base.isEmpty() ? "" : base + "/";
    List<String> names = new ArrayList<>();
    for (SecretDescription d : listDescriptions(prefix)) {
      if (!d.name().substring(prefix.length()).contains("/")) {
        names.add(d.name());
      }
    }
    names.sort(null);
    return getMany(names, GetOptions.none());
  }

  /**
   * Returns the present secrets in request order ({@code BatchGetSecretValue} in chunks of 20;
   * per-name reads when a {@code version} is requested).
   */
  @Override
  public Map<String, SecretValue> getMany(List<String> names, GetOptions opts) {
    if (opts.version().isPresent()) {
      return super.getMany(names, opts);
    }
    Set<String> unique = new LinkedHashSet<>(names);
    Map<String, String> byFull = new LinkedHashMap<>();
    for (String n : unique) {
      byFull.put(fullName(n, opts.path().orElse(null)), n);
    }
    List<String> ids = new ArrayList<>(byFull.keySet());
    Map<String, SecretValue> found = new HashMap<>();
    for (int i = 0; i < ids.size(); i += AwsSecretsManagerClient.BATCH_GET_MAX_IDS) {
      List<String> chunk =
          ids.subList(i, Math.min(ids.size(), i + AwsSecretsManagerClient.BATCH_GET_MAX_IDS));
      BatchGetResult result = client.batchGetSecretValue(chunk);
      for (BatchGetError e : result.errors()) {
        if (e.errorCode() != null && MISSING_BATCH_CODES.contains(e.errorCode())) {
          continue;
        }
        throw AwsSecretsManagerException.of(
            e.code(),
            "secrets.getMany "
                + Models.nz(e.secretId())
                + ": "
                + (e.errorCode() == null ? "error" : e.errorCode()),
            null,
            null,
            null,
            null);
      }
      for (AwsSecretValue v : result.secretValues()) {
        String requested =
            byFull.containsKey(v.name()) ? byFull.get(v.name()) : byFull.get(v.arn());
        if (requested != null) {
          found.put(requested, v.value());
        }
      }
    }
    Map<String, SecretValue> ordered = new LinkedHashMap<>();
    for (String n : unique) {
      SecretValue v = found.get(n);
      if (v != null) {
        ordered.put(n, v);
      }
    }
    return ordered;
  }

  @Override
  protected String putSecret(String name, byte[] value, SetOptions opts) {
    if (opts.cas().isPresent()) {
      throw new ValidationException(
          "secrets.set " + name + ": AWS Secrets Manager has no compare-and-set (cas)");
    }
    String id = fullName(name, opts.path().orElse(null));
    Models.Encoded encoded = Models.encodeBytes(value);
    Object input = encoded.string() != null ? encoded.string() : value;
    try {
      return putExisting(id, input, opts);
    } catch (AwsSecretsManagerException e) {
      if (e.code() != ErrorCode.NOT_FOUND) {
        throw e;
      }
    }
    try {
      CreateSecretOptions.Builder c =
          CreateSecretOptions.builder().description(opts.description().orElse(null));
      if (!opts.tags().isEmpty()) {
        c.tags(opts.tags());
      }
      SecretWriteResult created = client.createSecret(id, input, c.build());
      return created.versionId() == null ? "" : created.versionId();
    } catch (AwsSecretsManagerException e) {
      // Lost a create race: the secret exists now, write the value as a new version.
      if (e.code() == ErrorCode.CONFLICT
          && AwsErrors.awsErrorCode(e).filter("ResourceExistsException"::equals).isPresent()) {
        return putExisting(id, input, opts);
      }
      throw e;
    }
  }

  private String putExisting(String id, Object input, SetOptions opts) {
    PutSecretValueResult out = client.putSecretValue(id, input);
    if (!opts.tags().isEmpty()) {
      client.tagResource(id, opts.tags());
    }
    if (opts.description().isPresent()) {
      client.updateSecret(
          id, UpdateSecretOptions.builder().description(opts.description().get()).build());
    }
    return out.versionId();
  }

  @Override
  protected void removeSecret(String name, DeleteOptions opts) {
    if (!opts.versions().isEmpty()) {
      throw new ValidationException(
          "secrets.delete "
              + name
              + ": AWS Secrets Manager cannot delete single versions; use updateSecretVersionStage");
    }
    String id = fullName(name, opts.path().orElse(null));
    // Required: a forced delete of a missing secret succeeds on AWS.
    if (describe(id).isEmpty()) {
      throw new NotFoundException("secrets.delete " + id + ": not found");
    }
    client.deleteSecret(
        id,
        opts.permanent()
            ? DeleteSecretOptions.builder().forceDeleteWithoutRecovery(true).build()
            : DeleteSecretOptions.builder().recoveryWindowDays(recoveryWindowDays).build());
  }

  @Override
  protected Optional<SecretMetadata> fetchMetadata(String name, GetOptions opts) {
    return describe(fullName(name, opts.path().orElse(null)))
        .map(AwsSecretsManagerSecretsProvider::toMetadata);
  }

  /** DescribeSecret; empty when missing or scheduled for deletion. */
  private Optional<SecretDescription> describe(String id) {
    try {
      SecretDescription d = client.describeSecret(id);
      return d.pendingDeletion() ? Optional.empty() : Optional.of(d);
    } catch (AwsSecretsManagerException e) {
      if (isMissing(e)) {
        return Optional.empty();
      }
      throw e;
    }
  }

  /** Stops the watchers of this provider. Idempotent. */
  @Override
  public void close() {
    super.close();
    if (onClose != null) {
      onClose.run();
    }
  }
}
