# syntax=docker/dockerfile:1
FROM node:22.20.0-bookworm-slim AS dashboard
WORKDIR /src/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY VERSION /src/VERSION
COPY frontend ./
RUN npm run build

FROM scratch AS dashboard-artifact
COPY --from=dashboard /src/frontend/dist/ /

FROM golang:1.25-bookworm AS build
ARG APP_VERSION
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
COPY migrations ./migrations
RUN test -n "$APP_VERSION" && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w -X github.com/verdantflarehub/verdantflare-app-network/internal/buildinfo.Version=$APP_VERSION" -o /out/network ./cmd/network

FROM gcr.io/distroless/static-debian12:nonroot
ARG APP_VERSION
LABEL org.opencontainers.image.version=$APP_VERSION
COPY --from=build /out/network /app/network
COPY --from=dashboard /src/frontend/dist /app/dashboard
ENV NETWORK_LISTEN_ADDR=0.0.0.0:8080
EXPOSE 8080
USER 65532:65532
ENTRYPOINT ["/app/network"]
CMD ["serve"]
