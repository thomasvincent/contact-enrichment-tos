# Deployments

This directory contains production-ready deployment assets for the Java service.

## Helm (Kubernetes)

Chart: `deployments/helm/contact-enrichment`

- Non-sensitive config via ConfigMap; sensitive values via Secret.
- Security hardened: runAsNonRoot, read-only FS, PodDisruptionBudget, optional HPA, NetworkPolicy, and Prometheus ServiceMonitor.

Quick start (dev):

```sh
helm upgrade --install contact-enrichment deployments/helm/contact-enrichment \
  --set image.repository=ghcr.io/thomasvincent/contact-enrichment-java \
  --set image.tag=latest \
  --set envFrom.secretName=contact-enrichment-secret \
  --set envFrom.configMapName=contact-enrichment-config
```

Create resources:

```sh
kubectl create secret generic contact-enrichment-secret \
  --from-literal=DATABASE_URL=jdbc:postgresql://postgresql:5432/contact_enrichment \
  --from-literal=DATABASE_USERNAME=app \
  --from-literal=DATABASE_PASSWORD=app \
  --from-literal=JWT_SECRET=change-me

kubectl create configmap contact-enrichment-config \
  --from-literal=SERVER_PORT=8080 \
  --from-literal=REDIS_HOST=redis \
  --from-literal=REDIS_PORT=6379
```

## Nomad

Job: `deployments/nomad/contact-enrichment.nomad.hcl`

- Uses Vault (`kv/data/contact-enrichment`) to template secrets into environment.
- Rolling updates and restart policy enabled.

Validate:

```sh
nomad job validate deployments/nomad/contact-enrichment.nomad.hcl
```

Run (example):

```hcl
variable "image" { default = "ghcr.io/thomasvincent/contact-enrichment-java:latest" }
```

Then:

```sh
nomad job run deployments/nomad/contact-enrichment.nomad.hcl
```
