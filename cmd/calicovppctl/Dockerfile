FROM --platform=${BUILDPLATFORM} golang:1.24 AS builder

WORKDIR /src
COPY go.mod go.sum /src
RUN go mod download

COPY *.go /src

ARG TARGETOS
ARG TARGETARCH

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
	go build \
    -ldflags="-s -w" -o /cmd/calicovppctl

FROM scratch
WORKDIR /
COPY --from=builder /cmd/calicovppctl /calicovppctl

CMD ["./calicovppctl"]
