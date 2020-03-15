FROM mariadb:10.3

# https://github.com/docker-library/mariadb/tree/master/10.3

ENV GOLANG_VERSION 1.13.8

RUN set -e;\
  apt-get update; \
  apt-get install -y git curl gcc libssl-dev && \
  curl -sL https://dl.google.com/go/go${GOLANG_VERSION}.linux-amd64.tar.gz | tar -C /usr/local -xz

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH
WORKDIR /opt

COPY go.mod main.go mysqlgo/
RUN cd mysqlgo && go run . && rm -rf /opt/mysqlgo
