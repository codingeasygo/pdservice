#!/bin/bash
set -xe
case "$1" in
  -i)
    if [ ! -d /home/pdsd ];then
      useradd pdsd
      mkdir -p /home/pdsd
      chown -R pdsd:pdsd /home/pdsd
    fi
    if [ ! -f /etc/systemd/system/pdservice.service ];then
       cp -f pdservice.service /etc/systemd/system/
    fi
    if [ ! -f /home/pdsd/conf/pdservice.properties ];then
      mkdir -p /home/pdsd/conf/
      cp -f conf/pdservice.properties /home/pdsd/conf/
    fi
    rm -rf /home/pdsd/pdservice
    mkdir -p /home/pdsd/pdservice
    cp -rf * /home/pdsd/pdservice
    chown -R pdsd:pdsd /home/pdsd
    systemctl enable pdservice.service
    ;;
  *)
    echo "Usage: ./pdservice-install.sh -i"
    ;;
esac
