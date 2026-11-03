#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
REPO_ROOT="$(cd "$APP_DIR/../.." && pwd)"
ENV_FILE="${TVC_DEMO_ENV_FILE:-$APP_DIR/.env.local}"

if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ENV_FILE"
  set +a
fi

AWS_REGION="${AWS_REGION:-eu-west-1}"
STACK_NAME="${TVC_DEMO_STACK_NAME:-zolana-privacy-wallet-demo}"
ECR_REPOSITORY="${TVC_DEMO_ECR_REPOSITORY:-zolana-privacy-wallet-demo}"
DEVNET_SOLANA_RPC_URL="${DEVNET_SOLANA_RPC_URL:-https://api.devnet.solana.com}"
NEXT_PUBLIC_HELIUS_API_KEY="${NEXT_PUBLIC_HELIUS_API_KEY:-${HELIUS_API_KEY:-}}"

if [[ -z "$NEXT_PUBLIC_HELIUS_API_KEY" ]]; then
  echo "NEXT_PUBLIC_HELIUS_API_KEY or HELIUS_API_KEY is required" >&2
  exit 1
fi

AWS_ACCOUNT_ID="$(aws sts get-caller-identity --query Account --output text)"
ECR_HOST="$AWS_ACCOUNT_ID.dkr.ecr.$AWS_REGION.amazonaws.com"
IMAGE_TAG="$(git -C "$REPO_ROOT" rev-parse --short=12 HEAD)-$(date -u +%Y%m%d%H%M%S)"
IMAGE_IDENTIFIER="$ECR_HOST/$ECR_REPOSITORY:$IMAGE_TAG"

if ! aws ecr describe-repositories \
  --region "$AWS_REGION" \
  --repository-names "$ECR_REPOSITORY" >/dev/null 2>&1; then
  aws ecr create-repository \
    --region "$AWS_REGION" \
    --repository-name "$ECR_REPOSITORY" \
    --image-tag-mutability IMMUTABLE \
    --image-scanning-configuration scanOnPush=true >/dev/null
fi
aws ecr put-lifecycle-policy \
  --region "$AWS_REGION" \
  --repository-name "$ECR_REPOSITORY" \
  --lifecycle-policy-text '{"rules":[{"rulePriority":1,"description":"Keep ten demo images","selection":{"tagStatus":"any","countType":"imageCountMoreThan","countNumber":10},"action":{"type":"expire"}}]}' >/dev/null

aws ecr get-login-password --region "$AWS_REGION" \
  | docker login --username AWS --password-stdin "$ECR_HOST" >/dev/null

DOCKER_BUILDKIT=1 docker buildx build \
  --platform linux/amd64 \
  --load \
  --secret id=helius_api_key,env=NEXT_PUBLIC_HELIUS_API_KEY \
  --file "$APP_DIR/Dockerfile" \
  --tag "$IMAGE_IDENTIFIER" \
  "$REPO_ROOT"
docker push "$IMAGE_IDENTIFIER"

aws cloudformation deploy \
  --region "$AWS_REGION" \
  --stack-name "$STACK_NAME" \
  --template-file "$SCRIPT_DIR/template.yaml" \
  --capabilities CAPABILITY_IAM \
  --no-fail-on-empty-changeset \
  --parameter-overrides \
    "ImageIdentifier=$IMAGE_IDENTIFIER" \
    "HeliusApiKey=$NEXT_PUBLIC_HELIUS_API_KEY" \
    "SolanaRpcUrl=$DEVNET_SOLANA_RPC_URL"

SERVICE_URL="$(aws cloudformation describe-stacks \
  --region "$AWS_REGION" \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='ServiceUrl'].OutputValue" \
  --output text)"

echo "Image: $IMAGE_IDENTIFIER"
echo "Demo:  $SERVICE_URL"
