SHELL := /bin/bash
REPO_ROOT := $(shell pwd)
JAVA_DIR := implementations/java
IMAGE := ghcr.io/$(shell echo ${GITHUB_REPOSITORY_OWNER:-thomasvincent})/contact-enrichment-java
TAG ?= dev
PLATFORMS ?= linux/amd64,linux/arm64

.PHONY: build test package clean docker-build docker-push helm-lint nomad-validate

build:
	cd $(JAVA_DIR) && ./mvnw -B -ntp clean compile

test:
	cd $(JAVA_DIR) && ./mvnw -B -ntp test

package:
	cd $(JAVA_DIR) && ./mvnw -B -ntp -DskipTests package

clean:
	cd $(JAVA_DIR) && ./mvnw -B -ntp clean

# Local single-arch build
docker-build:
	docker build \
	  --build-arg VERSION=$(TAG) \
	  --build-arg BUILD_DATE=$$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
	  --build-arg VCS_REF=$$(git rev-parse --short HEAD) \
	  -f implementations/java/Dockerfile \
	  -t $(IMAGE):$(TAG) \
	  .

# Multi-arch buildx build+push
# Usage: make docker-push TAG=$(git rev-parse --short HEAD)
docker-push:
	docker buildx build \
	  --platform $(PLATFORMS) \
	  --provenance=true --sbom=true \
	  --build-arg VERSION=$(TAG) \
	  --build-arg BUILD_DATE=$$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
	  --build-arg VCS_REF=$$(git rev-parse --short HEAD) \
	  -f implementations/java/Dockerfile \
	  -t $(IMAGE):$(TAG) -t $(IMAGE):latest \
	  --push .

helm-lint:
	helm lint deployments/helm/contact-enrichment

nomad-validate:
	nomad job validate deployments/nomad/contact-enrichment.nomad.hcl
