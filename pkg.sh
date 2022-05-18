#!/bin/bash
##############################
#####Setting Environments#####
echo "Setting Environments"
set -xe
export cpwd=`pwd`
export LD_LIBRARY_PATH=/usr/local/lib:/usr/lib
output=$cpwd/build
#### Package ####
srv_ver=v1.2.0
if [ "$2" != "" ];then
    srv_ver=$2
fi
srv_name=pdservice
build=$cpwd/build
output=$cpwd/build/$srv_name-$srv_ver
out_dir=$srv_name-$srv_ver
srv_out=$output/$srv_name
go_path=`go env GOPATH`
go_os=`go env GOOS`
go_arch=`go env GOARCH`

##build normal
cat <<EOF > version.go
package main

const Version = "$srv_ver"
EOF
echo "Build $srv_name normal executor..."
go build -o $srv_out/service github.com/codingeasygo/pdservice
cp -rf conf $srv_out
cp -rf discover/trigger.sh $srv_out/trigger_example.sh
cp -rf discover/finder.sh $srv_out/finder_example.sh
cp -rf pdservice-install.sh pdservice.service $srv_out
# apidoc -i shsapi -o $srv_out/www/apidoc
# git restore version.go
###
cd $output
out_tar=$srv_name-$go_os-$go_arch-$srv_ver.tar.gz
rm -f $out_tar
tar -czvf $build/$out_tar $srv_name

cd $cpwd

echo "Package $srv_name-$go_os-$go_arch-$srv_ver done..."