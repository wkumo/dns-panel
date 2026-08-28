FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dns-panel .
FROM alpine:3.22
RUN apk add --no-cache ca-certificates su-exec && addgroup -S -g 1000 app && adduser -S -D -H -u 1000 -G app app
WORKDIR /app
COPY --from=build /dns-panel /app/dns-panel
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh && mkdir /data && chown app:app /data
ENV DATA_DIR=/data LISTEN_ADDR=:48192
EXPOSE 48192
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
