FROM docker.io/golang AS builder
WORKDIR /build
COPY . .
ENV CGO_ENABLED=0
RUN go build

FROM scratch
COPY --from=builder /build/shortener /usr/bin/shortener
ENTRYPOINT ["/usr/bin/shortener"]
