job "contact-enrichment" {
  datacenters = ["dc1"]
  type = "service"

  update {
    max_parallel     = 1
    health_check     = "checks"
    min_healthy_time = "10s"
    healthy_deadline = "5m"
    stagger          = "30s"
  }

  group "app" {
    count = 2

    network {
      port "http" { to = 8080 }
    }

    restart {
      attempts = 3
      interval = "30s"
      delay    = "15s"
      mode     = "fail"
    }

    task "web" {
      driver = "docker"

      vault {
        policies = ["contact-enrichment"]
      }

      # Base environment (non-sensitive)
      env = {
        SPRING_PROFILES_ACTIVE = "prod"
        SERVER_PORT            = "8080"
      }

      # Template secrets from Vault into environment
      template {
        destination   = "secrets/env"
        env           = true
        change_mode   = "signal"
        change_signal = "SIGHUP"
        data = <<EOH
DATABASE_URL={{ with secret "kv/data/contact-enrichment" }}{{ .Data.data.DATABASE_URL }}{{ end }}
DATABASE_USERNAME={{ with secret "kv/data/contact-enrichment" }}{{ .Data.data.DATABASE_USERNAME }}{{ end }}
DATABASE_PASSWORD={{ with secret "kv/data/contact-enrichment" }}{{ .Data.data.DATABASE_PASSWORD }}{{ end }}
JWT_SECRET={{ with secret "kv/data/contact-enrichment" }}{{ .Data.data.JWT_SECRET }}{{ end }}
REDIS_HOST={{ with secret "kv/data/contact-enrichment" }}{{ .Data.data.REDIS_HOST }}{{ end }}
REDIS_PORT={{ with secret "kv/data/contact-enrichment" }}{{ .Data.data.REDIS_PORT }}{{ end }}
EOH
      }

      config {
        # Override via job variable or env (e.g., NOMAD_VAR_image)
        image      = "ghcr.io/thomasvincent/contact-enrichment-java:latest"
        ports      = ["http"]
        force_pull = true
      }

      resources {
        cpu    = 700
        memory = 512
      }

      service {
        name = "contact-enrichment"
        port = "http"
        check {
          type     = "http"
          path     = "/api/v1/health"
          interval = "10s"
          timeout  = "2s"
        }
      }
    }
  }
}
