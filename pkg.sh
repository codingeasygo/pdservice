#!/bin/bash
##############################
#####Setting Environments#####
echo "Setting Environments"
set -xe
export cpwd=`pwd`
export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib

srv_name=pdservice
srv_ver=$1
if [ "$1" == "" ];then
    srv_ver=`git rev-parse --abbrev-ref HEAD`
fi 

cat <<EOF > version.go
package main

const Version = "$srv_ver"
EOF

GOOS=linux go build -trimpath -v .

pub_srv=$2
if [ "$pub_srv" == "" ];then
    docker build --build-arg="HTTPS_PROXY=$HTTPS_PROXY" -t $srv_name:$srv_ver .
else
    docker build --build-arg="HTTPS_PROXY=$HTTPS_PROXY" -t $pub_srv/$srv_name:$srv_ver .
    docker push $pub_srv/$srv_name:$srv_ver
fi

echo "Package $srv_name-$srv_ver done..."
