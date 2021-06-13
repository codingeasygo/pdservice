#!/bin/bash

#########
echo "Setting Test Env"
docker rm -f docker-discover
mkdir -p test
docker run --privileged --restart always --name docker-discover -d \
    -e DOCKER_TLS_CERTDIR=/certs \
    -v `pwd`/test/certs/ca:/certs/ca \
    -v `pwd`/test/certs/client:/certs/client \
    -v `pwd`/test/data:/var/lib/docker \
    docker:dind
sleep 2 # wait started
docker exec docker-discover docker rm -f ds-srv-v1.0.0
docker exec docker-discover docker run -d --name ds-srv-v1.0.0 --restart always -P nginx
docker exec docker-discover docker rm -f ds-srv-v1.0.1
docker exec docker-discover docker run -d --name ds-srv-v1.0.1 --restart always -P nginx
#########
echo "Running Test"
mkdir -p build
pkgs="\
   github.com/codingeasygo/dockerdiscover/discover\
"
echo "mode: set" > build/all.cov
for p in $pkgs;
do
 if [ "$1" = "-u" ];then
  go get -u $p
 fi
 go test -v -timeout 20m -covermode count --coverprofile=build/c.cov $p
 cat build/c.cov | grep -v "mode" >> build/all.cov
done

gocov convert build/all.cov > build/coverage.json
cat build/coverage.json | gocov-html > build/coverage.html
cat build/all.cov | gocover-cobertura > build/coverage.xml
go tool cover -func build/all.cov | grep total