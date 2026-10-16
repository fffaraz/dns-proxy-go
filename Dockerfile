FROM golang:1.26 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /microdns-proxy .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /microdns-proxy /microdns-proxy
EXPOSE 5300/udp 5300/tcp
ENTRYPOINT ["/microdns-proxy", "-p", "5300"]
