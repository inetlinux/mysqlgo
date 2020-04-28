FROM centos:7

ADD mariadb.repo /etc/yum.repos.d/mariadb.repo

RUN yum update -y;\
    yum install -y MariaDB-server MariaDB-client curl iputils iproute telnet xz-utils tzdata socat

# add gosu for easy step-down from root
ENV GOSU_VERSION 1.12
RUN set -eux; \
    curl -o /usr/local/bin/gosu -SL "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-amd64"; \
    curl -o /usr/local/bin/gosu.asc -SL "https://github.com/tianon/gosu/releases/download/$GOSU_VERSION/gosu-amd64.asc"; \
    gpg --batch --keyserver hkps://keys.openpgp.org --recv-keys B42F6819007F00F88E364FD4036A9C25BF357DD4; \
    gpg --batch --verify /usr/local/bin/gosu.asc /usr/local/bin/gosu; \
    rm -f /usr/local/bin/gosu.asc /root/.gnupg/*; \
    chmod +x /usr/local/bin/gosu; \
    gosu --version; \
    gosu nobody true

RUN set -ex; \
    mkdir /docker-entrypoint-initdb.d; \
    rm -rf /var/lib/mysql; \
    mkdir -p /var/lib/mysql /var/run/mysqld; \
    chown -R mysql:mysql /var/lib/mysql /var/run/mysqld; \
    find /etc/my.cnf.d/ -name '*.cnf' -print0 \
        | xargs -0 egrep -lZ '^(bind-address|log)' \
        | xargs -rt -0 sed -ri 's/^(bind-address|log)/#&/'; \
    echo -e '[mysqld]\nskip-host-cache\nskip-name-resolve' > /etc/my.cnf.d/docker.cnf

VOLUME /var/lib/mysql
EXPOSE 3306

COPY docker-entrypoint.sh /usr/local/bin

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["mysqld"]
