FROM golang:1.24-alpine3.22 AS build-stage

WORKDIR /build

ENV CGO_ENABLED=0
ENV GOOS=linux

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go mod tidy -v && \
    go test -v ./... && \
    go build -v -o app ./cmd/main.go

FROM alpine:3.22 AS release-stage

WORKDIR /release

COPY --from=build-stage /build/app .

CMD ["./app"]
