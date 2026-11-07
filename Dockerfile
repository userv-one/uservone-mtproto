FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY core ./core
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w -buildid=" -o /uservone-media-dc-203 ./cmd/uservone-media-dc-203

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /uservone-media-dc-203 /uservone-media-dc-203
USER 65532:65532
EXPOSE 443
ENTRYPOINT ["/uservone-media-dc-203"]
CMD ["-config", "/etc/uservone/config.json"]
