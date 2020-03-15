# 介绍

用于测试golang编译的程序，且程序依赖于MariaDB环境。使用方法如下：

    docker run --rm -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -v your-init.sql:/docker-entrypoint-initdb.d/init.sql inetlinux/mysqlgo

**构建镜像**

    docker build -t inetlinux/mysqlgo .
