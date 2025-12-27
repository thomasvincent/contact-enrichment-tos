job "contact-enrichment" {
  datacenters = ["dc1"]
  type = "service"

  group "app" {
    count = 1

    network {
      port "http" { to = 8080 }
    }

    task "web" {
      driver = "docker"

      env = {
        SPRING_PROFILES_ACTIVE = "prod"
        SERVER_PORT            = "8080"
        DATABASE_URL           = "${NOMAD_DATABASE_URL}"
        DATABASE_USERNAME      = "${NOMAD_DATABASE_USERNAME}"
        DATABASE_PASSWORD      = "${NOMAD_DATABASE_PASSWORD}"
        REDIS_HOST             = "${NOMAD_REDIS_HOST}"
        REDIS_PORT             = "${NOMAD_REDIS_PORT}"
        JWT_SECRET             = "${NOMAD_JWT_SECRET}"
      }

      config {
        image = "ghcr.io/thomasvincent/contact-enrichment-java:latest"
        ports = ["http"]
        force_pull = true
      }

      resources {
        cpu    = 500
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
