// Command example shows the AWS Secrets Manager Go SDK: configuration from the
// standard AWS environment, health and ping, a secret round trip, JSON fields,
// the SecretsProvider and the version-stage aware cache.
//
// Against the Docker emulator (Moto) or real AWS:
//
//	AWS_REGION=us-east-1 AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
//	GROW_AWS_SECRETS_MANAGER_URL=http://localhost:5000 go run .
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	asm "github.com/grow-codes-packages/aws-secrets-manager/go"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := asm.ConfigFromEnv()
	if err != nil {
		return err // CONFIG error naming the variable, never its value
	}
	cfg.Logger = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	fmt.Println("config:", cfg) // credentials print as [REDACTED]

	client, err := asm.NewClient(cfg)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	health, err := client.Health(ctx)
	if err != nil {
		return err
	}
	fmt.Printf("health: healthy=%t status=%s\n", health.Healthy, health.Status)
	latency, err := client.Ping(ctx)
	if errors.Is(err, asm.ErrAuthentication) {
		return fmt.Errorf("check the AWS credentials: %w", err)
	} else if err != nil {
		return err
	}
	fmt.Println("ping:", latency.Round(time.Millisecond))

	name := fmt.Sprintf("grow-example/%d/db", time.Now().UnixNano())
	created, err := client.CreateSecret(ctx, name, map[string]any{"username": "app", "password": "s3cr3t"},
		&asm.CreateSecretOptions{Description: "example", Tags: map[string]string{"owner": "example"}})
	if err != nil {
		return err
	}
	defer func() {
		_, _ = client.DeleteSecret(context.Background(), name, &asm.DeleteSecretOptions{ForceDeleteWithoutRecovery: true})
	}()
	fmt.Println("created version:", created.VersionID)

	user, _, err := client.GetJSONField(ctx, name, "username", nil)
	if err != nil {
		return err
	}
	fmt.Println("username:", user)

	value, err := client.GetSecretValue(ctx, name, nil)
	if err != nil {
		return err
	}
	fmt.Println("value:", value.Value) // prints SecretValue([REDACTED])

	pw, err := client.GetRandomPassword(ctx, &asm.RandomPasswordOptions{Length: 24, ExcludePunctuation: true})
	if err != nil {
		return err
	}
	if _, err := client.PutSecretValue(ctx, name, map[string]any{"username": "app", "password": pw.Reveal()}, nil); err != nil {
		return err
	}

	for d, err := range client.ListSecrets(ctx, &asm.ListSecretsOptions{
		Filters: []asm.SecretFilter{{Key: asm.FilterName, Values: []string{"grow-example/"}}},
	}) {
		if err != nil {
			return err
		}
		fmt.Println("listed:", d.Name, "versions:", len(d.VersionIDsToStages))
	}

	secrets, err := client.Secrets()
	if err != nil {
		return err
	}
	exists, err := secrets.Exists(ctx, name, nil)
	if err != nil {
		return err
	}
	fmt.Println("exists:", exists)

	cache, err := client.SecretCache(nil) // TTL 1 h, stage AWSCURRENT
	if err != nil {
		return err
	}
	if _, err := cache.GetSecretValue(ctx, name, nil); err != nil {
		return err
	}
	fmt.Printf("cache: %+v\n", cache.Stats())

	_, err = client.GetSecretValue(ctx, name+"-missing", nil)
	fmt.Println("missing secret is NOT_FOUND:", errors.Is(err, asm.ErrNotFound))
	return nil
}
