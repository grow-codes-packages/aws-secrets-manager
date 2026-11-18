#!/bin/sh
# Bootstrap for the AWS Secrets Manager SDK fixture (Moto with IAM auth enabled).
# POSIX sh + curl (curlimages/curl). Idempotent: a re-run on the same stack reuses
# the stored keys, tolerates existing users/secrets and rewrites /bootstrap/env.
#
# Creates:
#   - IAM user grow-sdk-admin    (policy Allow * on *)            -> AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
#   - IAM user grow-sdk-readonly (secretsmanager read actions only) -> GROW_TEST_READONLY_*
#   - seed secrets grow-bootstrap/seed-json (SecretString) and grow-bootstrap/seed-binary (SecretBinary)
# Writes KEY=value lines to $BOOTSTRAP_DIR/env (0644). Keys are Moto-generated fakes, valid only
# inside this disposable emulator; they are never printed.
set -eu

URL=${ASM_URL:-http://aws-secrets-manager:5000}
REGION=${ASM_REGION:-us-east-1}
DIR=${BOOTSTRAP_DIR:-/bootstrap}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$DIR"
umask 077

log() { echo "bootstrap: $*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# curl with a few retries on connection-level failures (Moto can reset the first connection).
xcurl() {
  n=0
  while :; do
    if curl "$@"; then return 0; fi
    rc=$?
    n=$((n + 1))
    case $rc in 7|52|56) [ $n -lt 10 ] || return $rc; sleep 1 ;; *) return $rc ;; esac
  done
}

# iam <access-key> <secret-key> <form args...>  -> prints HTTP status, body in $TMP/body
iam() {
  _ak=$1 _sk=$2; shift 2
  xcurl -sS -o "$TMP/body" -w '%{http_code}' \
    --aws-sigv4 "aws:amz:us-east-1:iam" --user "$_ak:$_sk" \
    --data-urlencode "Version=2010-05-08" "$@" "$URL/"
}

# sm <Operation> <json>  -> prints HTTP status, body in $TMP/body (signed with the admin key)
sm() {
  xcurl -sS -o "$TMP/body" -w '%{http_code}' \
    --aws-sigv4 "aws:amz:$REGION:secretsmanager" --user "$ADMIN_AK:$ADMIN_SK" \
    -H "X-Amz-Target: secretsmanager.$1" -H 'Content-Type: application/x-amz-json-1.1' \
    --data-binary "$2" "$URL/"
}

xml_val() { grep -o "<$1>[^<]*</$1>" "$TMP/body" | head -n 1 | sed 's/<[^>]*>//g'; }
json_str() { tr -d '\n' <"$TMP/body" | grep -o "\"$1\": *\"[^\"]*\"" | head -n 1 | sed 's/.*: *"\(.*\)"/\1/'; }

ADMIN_POLICY='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
RO_POLICY='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["secretsmanager:GetSecretValue","secretsmanager:BatchGetSecretValue","secretsmanager:DescribeSecret","secretsmanager:ListSecrets","secretsmanager:ListSecretVersionIds","secretsmanager:GetResourcePolicy","secretsmanager:GetRandomPassword"],"Resource":"*"}]}'

# --- 1. admin user (uses the 3 unauthenticated actions; must be the first AWS calls) ---------
if [ -s "$DIR/admin.env" ]; then
  . "$DIR/admin.env"
  log "reusing admin key"
else
  code=$(iam bootstrap bootstrap --data-urlencode Action=CreateUser --data-urlencode UserName=grow-sdk-admin)
  case $code in
    200) ;;
    409) die "grow-sdk-admin exists but its key is lost; recreate the stack (docker compose down -v)" ;;
    *) die "CreateUser grow-sdk-admin: HTTP $code" ;;
  esac
  code=$(iam bootstrap bootstrap --data-urlencode Action=PutUserPolicy --data-urlencode UserName=grow-sdk-admin \
    --data-urlencode PolicyName=grow-sdk-admin --data-urlencode "PolicyDocument=$ADMIN_POLICY")
  [ "$code" = 200 ] || die "PutUserPolicy grow-sdk-admin: HTTP $code"
  code=$(iam bootstrap bootstrap --data-urlencode Action=CreateAccessKey --data-urlencode UserName=grow-sdk-admin)
  [ "$code" = 200 ] || die "CreateAccessKey grow-sdk-admin: HTTP $code"
  ADMIN_AK=$(xml_val AccessKeyId) ADMIN_SK=$(xml_val SecretAccessKey)
  [ -n "$ADMIN_AK" ] && [ -n "$ADMIN_SK" ] || die "CreateAccessKey: could not parse key"
  printf 'ADMIN_AK=%s\nADMIN_SK=%s\n' "$ADMIN_AK" "$ADMIN_SK" >"$DIR/admin.env"
  log "created admin user + key"
fi

# --- 2. admin key must work (signed ListSecrets) ---------------------------------------------
code=$(sm ListSecrets '{"MaxResults":1}')
[ "$code" = 200 ] || die "signed ListSecrets with admin key: HTTP $code (is IAM auth on?)"

# --- 3. read-only user -----------------------------------------------------------------------
code=$(iam "$ADMIN_AK" "$ADMIN_SK" --data-urlencode Action=CreateUser --data-urlencode UserName=grow-sdk-readonly)
case $code in 200|409) ;; *) die "CreateUser grow-sdk-readonly: HTTP $code" ;; esac
code=$(iam "$ADMIN_AK" "$ADMIN_SK" --data-urlencode Action=PutUserPolicy --data-urlencode UserName=grow-sdk-readonly \
  --data-urlencode PolicyName=grow-sdk-readonly --data-urlencode "PolicyDocument=$RO_POLICY")
[ "$code" = 200 ] || die "PutUserPolicy grow-sdk-readonly: HTTP $code"
if [ -s "$DIR/readonly.env" ]; then
  . "$DIR/readonly.env"
else
  code=$(iam "$ADMIN_AK" "$ADMIN_SK" --data-urlencode Action=CreateAccessKey --data-urlencode UserName=grow-sdk-readonly)
  [ "$code" = 200 ] || die "CreateAccessKey grow-sdk-readonly: HTTP $code"
  RO_AK=$(xml_val AccessKeyId) RO_SK=$(xml_val SecretAccessKey)
  [ -n "$RO_AK" ] && [ -n "$RO_SK" ] || die "CreateAccessKey readonly: could not parse key"
  printf 'RO_AK=%s\nRO_SK=%s\n' "$RO_AK" "$RO_SK" >"$DIR/readonly.env"
fi

# --- 4. seed secrets (read-only fixtures; tests create their own names under a run prefix) ---
seed() { # seed <name> <json-body-for-CreateSecret>
  code=$(sm CreateSecret "$2")
  case $code in
    200) log "seeded $1" ;;
    400) grep -q ResourceExistsException "$TMP/body" || die "CreateSecret $1: HTTP 400" ;;
    *) die "CreateSecret $1: HTTP $code" ;;
  esac
  code=$(sm DescribeSecret "{\"SecretId\":\"$1\"}")
  [ "$code" = 200 ] || die "DescribeSecret $1: HTTP $code"
  json_str ARN
}
SEED_JSON_ARN=$(seed grow-bootstrap/seed-json \
  '{"Name":"grow-bootstrap/seed-json","ClientRequestToken":"00000000-0000-4000-8000-000000000001","Description":"Grow SDK bootstrap seed (JSON string)","SecretString":"{\"username\":\"seed-user\",\"password\":\"seed-pass-123\",\"port\":5432,\"enabled\":true}","Tags":[{"Key":"grow:fixture","Value":"seed"},{"Key":"kind","Value":"json"}]}')
# SecretBinary = base64 of bytes 00 01 02 fe ff (not valid UTF-8)
SEED_BIN_ARN=$(seed grow-bootstrap/seed-binary \
  '{"Name":"grow-bootstrap/seed-binary","ClientRequestToken":"00000000-0000-4000-8000-000000000002","Description":"Grow SDK bootstrap seed (binary)","SecretBinary":"AAEC/v8=","Tags":[{"Key":"grow:fixture","Value":"seed"},{"Key":"kind","Value":"binary"}]}')

# --- 5. env file (atomic) --------------------------------------------------------------------
cat >"$DIR/env.tmp" <<EOF
AWS_REGION=$REGION
AWS_DEFAULT_REGION=$REGION
AWS_ACCESS_KEY_ID=$ADMIN_AK
AWS_SECRET_ACCESS_KEY=$ADMIN_SK
AWS_ENDPOINT_URL_SECRETS_MANAGER=$URL
AWS_EC2_METADATA_DISABLED=true
GROW_AWS_SECRETS_MANAGER_URL=$URL
GROW_AWS_SECRETS_MANAGER_REGION=$REGION
GROW_TEST_ACCOUNT_ID=123456789012
GROW_TEST_READONLY_ACCESS_KEY_ID=$RO_AK
GROW_TEST_READONLY_SECRET_ACCESS_KEY=$RO_SK
GROW_TEST_SEED_JSON_SECRET=grow-bootstrap/seed-json
GROW_TEST_SEED_JSON_SECRET_ARN=$SEED_JSON_ARN
GROW_TEST_SEED_BINARY_SECRET=grow-bootstrap/seed-binary
GROW_TEST_SEED_BINARY_SECRET_ARN=$SEED_BIN_ARN
GROW_TEST_EMULATOR=moto
EOF
chmod 0644 "$DIR/env.tmp"
mv -f "$DIR/env.tmp" "$DIR/env"
log "wrote $DIR/env ($(wc -l <"$DIR/env") lines)"
