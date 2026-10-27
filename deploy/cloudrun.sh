#!/bin/bash
# Deploy EdgeGuard to Google Cloud Run with a verified rollout:
#   1. build the image with Cloud Build and deploy it as a tagged revision taking 0% traffic
#   2. run the black-box integration suite against that revision's private URL
#   3. only if it passes, shift 100% of traffic to it; otherwise the old revision keeps serving
#
# Run from Google Cloud Shell in the repo root:
#   PROJECT=my-project bash deploy/cloudrun.sh
# Optional (Microsoft Entra ID): ENTRA_TENANT_ID=<tenant guid> ENTRA_CLIENT_ID=<app client id>
set -euo pipefail
PROJECT=${PROJECT:?set PROJECT}
REGION=${REGION:-us-central1}
SERVICE=${SERVICE:-edgeguard}
gcloud config set project "$PROJECT" >/dev/null
gcloud services enable run.googleapis.com cloudbuild.googleapis.com secretmanager.googleapis.com artifactregistry.googleapis.com >/dev/null

secret() { # create a secret once; never overwrite
  local name=$1 value=$2
  if ! gcloud secrets describe "$name" >/dev/null 2>&1; then
    printf '%s' "$value" | gcloud secrets create "$name" --data-file=- --replication-policy=automatic >/dev/null
    echo "created secret $name"
  fi
}
secret edgeguard-admin-key "$(openssl rand -hex 24)"
secret edgeguard-demo-signing-key "$(openssl genrsa 2048 2>/dev/null)"

SA=$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')-compute@developer.gserviceaccount.com
for s in edgeguard-admin-key edgeguard-demo-signing-key; do
  gcloud secrets add-iam-policy-binding "$s" --member="serviceAccount:$SA" --role=roles/secretmanager.secretAccessor >/dev/null
done

ENV="EdgeGuard__Demo__Enabled=true"
if [[ -n "${ENTRA_TENANT_ID:-}" && -n "${ENTRA_CLIENT_ID:-}" ]]; then
  ENV="$ENV,EdgeGuard__Entra__TenantId=$ENTRA_TENANT_ID"
  ENV="$ENV,EdgeGuard__Entra__Audiences=api://$ENTRA_CLIENT_ID;$ENTRA_CLIENT_ID"
  ENV="$ENV,EdgeGuard__Entra__SpaClientId=$ENTRA_CLIENT_ID"
  ENV="$ENV,EdgeGuard__Entra__Scope=api://$ENTRA_CLIENT_ID/access_as_user"
fi

FIRST_DEPLOY=false
gcloud run services describe "$SERVICE" --region "$REGION" >/dev/null 2>&1 || FIRST_DEPLOY=true
TAG="c$(date +%Y%m%d%H%M%S)"

COMMON=(--source . --region "$REGION" --port 8080 --cpu 1 --memory 512Mi --concurrency 250
  --min-instances 0 --max-instances 1 --cpu-boost --allow-unauthenticated
  --set-env-vars "^;;^${ENV//,/;;}"
  --set-secrets "EdgeGuard__AdminKey=edgeguard-admin-key:latest,EdgeGuard__Demo__SigningKeyPem=edgeguard-demo-signing-key:latest")

if $FIRST_DEPLOY; then
  gcloud run deploy "$SERVICE" "${COMMON[@]}" --quiet
  URL=$(gcloud run services describe "$SERVICE" --region "$REGION" --format='value(status.url)')
else
  gcloud run deploy "$SERVICE" "${COMMON[@]}" --no-traffic --tag "$TAG" --quiet
  URL=$(gcloud run services describe "$SERVICE" --region "$REGION" --format="value(status.traffic[?tag=='$TAG'].url)" | tr -d "[]'")
  [[ -z "$URL" ]] && URL="https://$TAG---$(gcloud run services describe "$SERVICE" --region "$REGION" --format='value(status.url)' | sed 's|https://||')"
fi

echo "verifying $URL"
python3 -m pip install -q --user pytest requests >/dev/null
EDGEGUARD_URL="$URL" EDGEGUARD_ADMIN_KEY="$(gcloud secrets versions access latest --secret=edgeguard-admin-key)" \
  python3 -m pytest -q tests/integration || { echo "verification FAILED; traffic left on the previous revision"; exit 1; }

if ! $FIRST_DEPLOY; then
  gcloud run services update-traffic "$SERVICE" --region "$REGION" --to-tags "$TAG=100" --quiet
fi
echo "live: $(gcloud run services describe "$SERVICE" --region "$REGION" --format='value(status.url)')"
