FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /microdns-proxy .
RUN mkdir /whois-cache

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /microdns-proxy /microdns-proxy
COPY --from=build --chown=65534:65534 /whois-cache /whois-cache
ADD --chmod=644 https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts /stevenblack.txt
ADD --chmod=644 https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@latest/adblock/multi.txt /hagezi-multi.txt
COPY config.toml /config.toml
USER 65534:65534
EXPOSE 5300/udp 5300/tcp 8080/tcp
ENTRYPOINT ["/microdns-proxy"]
