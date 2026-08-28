FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dns-panel .
FROM alpine:3.22
RUN apk add --no-cache ca-certificates && addgroup -S app && adduser -S app -G app
WORKDIR /app
COPY --from=build /dns-panel /app/dns-panel
RUN mkdir /data && chown app:app /data
USER app
ENV DATA_DIR=/data LISTEN_ADDR=:48192
EXPOSE 48192
ENTRYPOINT ["/app/dns-panel"]
