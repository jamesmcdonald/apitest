FROM golang AS gobuild

WORKDIR /build/app
COPY . .
RUN CGO_ENABLED=0 go build -o app .

FROM cgr.dev/chainguard/wolfi-base

WORKDIR /opt/app
COPY --from=gobuild /build/app/app .

CMD ["./app"]
