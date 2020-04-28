# 介绍

本仓库会构建2种docker镜像：

* inetlinux/mariadb:10.3 and inetlinux/mariadb:10.4 - 基于CentOS 7的MariaDB镜像
* inetlinux/mysqlgo - 基于inetlinux/mariadb:10.4的Golang镜像，此镜像主要用于编译golang程序，可用于在依赖MariaDB golang程序的自动化测试。

```
docker run --rm -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -v your-init.sql:/docker-entrypoint-initdb.d/init.sql inetlinux/mariadb:10.4
docker run --rm -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -v your-init.sql:/docker-entrypoint-initdb.d/init.sql inetlinux/mysqlgo
```



**构建镜像**

    docker build -t inetlinux/mysqlgo .
