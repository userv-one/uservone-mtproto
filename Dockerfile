FROM golang:1.25-alpine AS build
WORKDIR /src
ARG VERSION=v0.3.0
COPY go.mod ./
COPY core ./core
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -buildid= -X main.version=$VERSION" -o /uservone-mtproto ./cmd/uservone-mtproto

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /uservone-mtproto /uservone-mtproto
USER 65532:65532
EXPOSE 443
ENTRYPOINT ["/uservone-mtproto"]
CMD ["-config", "/etc/mtproto/config.json"]
