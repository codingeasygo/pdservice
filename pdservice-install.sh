#!/bin/bash
set -xe
case "$1" in
  -i)
    if [ ! -f /etc/systemd/system/pdservice.service ];then
       cp -f pdservice.service /etc/systemd/system/
    fi
    if [ ! -f /root/pdsd/conf/pdservice.properties ];then
      mkdir -p /root/pdsd/conf/
      cp -f conf/pdservice.properties /root/pdsd/conf/
    fi
    rm -rf /root/pdsd/pdservice
    mkdir -p /root/pdsd/pdservice
    cp -rf * /root/pdsd/pdservice
    chown -R pdsd:pdsd /root/pdsd
    systemctl enable pdservice.service
    ;;
  *)
    echo "Usage: ./pdservice-install.sh -i"
    ;;
esac
