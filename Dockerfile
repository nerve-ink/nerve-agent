# syntax=docker/dockerfile:1

FROM golang:1.25-alpine AS build

WORKDIR /src
RUN apk add --no-cache ca-certificates

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/nerve-agent .

FROM alpine:3.22

RUN apk upgrade --no-cache \
  && apk add --no-cache ca-certificates \
  && addgroup -S nerve \
  && adduser -S -G nerve -h /var/lib/nerve-agent nerve

COPY --from=build /out/nerve-agent /usr/local/bin/nerve-agent

USER nerve
WORKDIR /var/lib/nerve-agent

ENTRYPOINT ["nerve-agent"]
CMD ["-server", "api.nerve.ink:443"]
