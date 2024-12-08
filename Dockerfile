FROM golang:1.23-alpine AS build-env

RUN apk add --no-cache git gcc musl-dev
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build ./cmd/portrecon

FROM alpine:3.20.3
RUN apk add --no-cache bind-tools ca-certificates chromium
COPY --from=build-env /app/portrecon /usr/local/bin/

ENTRYPOINT ["portrecon"]