# Multi-stage build from source, used by the GitHub Action (action.yml).
#
# GitHub requires Docker container actions to run as the default (root) user
# and recommends against WORKDIR: the runner mounts the workspace owned by its
# own user and sets the working directory itself. So this image uses the
# root distroless variant and sets neither USER nor WORKDIR. It still has no
# shell or package manager, and runs in the runner's throwaway container.
# The published image (build/Dockerfile.release) runs as nonroot.
#
# Bases are pinned by digest; Dependabot keeps them current.

FROM golang:1.27.3-alpine@sha256:d530cf60723abf1ffae0cd16bb546b379ec0550d2f3815e5b16ed69dbc00fba4 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download && go mod verify
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=action" -o /out/oraclint ./cmd/oraclint

FROM gcr.io/distroless/static@sha256:15f8637509792e05b97d83451b0b6ccfa4abd548f997e406ac1e72c87fe1fa78
COPY --from=build /out/oraclint /usr/bin/oraclint
ENTRYPOINT ["/usr/bin/oraclint"]
