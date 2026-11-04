FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /microdns-proxy .
RUN mkdir /data

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /microdns-proxy /microdns-proxy
COPY --from=build --chown=65534:65534 /data /data
COPY config.toml /config.toml
WORKDIR /data
USER 65534:65534
EXPOSE 5300/udp 5300/tcp
ENTRYPOINT ["/microdns-proxy"]
CMD ["/config.toml"]
