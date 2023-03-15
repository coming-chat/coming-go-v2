FROM golang:bullseye AS builder

LABEL stage=gobuilder

ENV CGO_ENABLED 1
ENV GOOS linux
ENV GOPATH /usr/lib/go

WORKDIR /home/build

COPY . .
RUN go mod download
RUN cp -r /usr/lib/go/pkg/mod/github.com/coming-chat/zkgroup\@v0.7.0-5/lib/ /usr/lib/
RUN cp -r /usr/lib/go/pkg/mod/github.com/coming-chat/zkgroup\@v0.7.0-5/lib/ ./lib/
RUN go build -o coming-go-client ./cmd/textsecure/main.go

FROM debian

COPY --from=builder /home/build/lib/ /usr/lib/
ENV TZ Asia/Shanghai

WORKDIR /home/runner
COPY --from=builder /home/build/coming-go-client /home/runner/coming-go-client

CMD ["./coming-go-client"]

