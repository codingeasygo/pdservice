#!/bin/bash
##############################
#####Setting Environments#####
echo "Setting Environments"
set -e
export cpwd=`pwd`
export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib
export PATH=$PATH:$GOPATH/bin:$HOME/bin:$GOROOT/bin
output=$cpwd/build
#### Package ####
srv_name=pdservice
srv_out=$output/$srv_name

rm -rf $srv_out
mkdir -p $srv_out
srv_ver=v0.1.0
##build normal
head_sha=`git rev-parse --short HEAD`
cat <<EOF > version.go
package main

const Version = "$srv_ver-$head_sha"
EOF
echo "Build $srv_name normal executor..."
go build -o $srv_out/pdsd github.com/codingeasygo/pdservice	
cp -rf conf $srv_out
cp -rf discover/trigger.sh $srv_out/trigger_example.sh
cp -rf discover/finder.sh $srv_out/finder_example.sh
cp -rf pdservice-install.sh pdservice.service $srv_out
# apidoc -i shsapi -o $srv_out/www/apidoc
git restore version.go
###
cd $output
rm -f $srv_name-$srv_ver-$head_sha-`uname`.tar.gz
tar -czvf $srv_name-$srv_ver-$head_sha-`uname`.tar.gz $srv_name
if [ "$1" != "" ];then
    scp $srv_name-$srv_ver-$head_sha-`uname`.tar.gz $1
fi
cd $cpwd
echo "Package $srv_name-$srv_ver-$head_sha done..."