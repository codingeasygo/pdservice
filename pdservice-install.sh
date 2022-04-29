#!/bin/bash
set -xe
case "$1" in
  -i)
    if [ ! -d /home/pds ];then
      useradd pds
      mkdir -p /home/pds
      chown -R pds:pds /home/pds
    fi
    if [ ! -f /etc/systemd/system/pdservice.service ];then
       cp -f pdservice.service /etc/systemd/system/
    fi
    if [ ! -f /home/pds/conf/pdservice.properties ];then
      mkdir -p /home/pds/conf/
      cp -f conf/pdservice.properties /home/pds/conf/
    fi
    rm -rf /home/pds/pdservice
    mkdir -p /home/pds/pdservice
    cp -rf * /home/pds/pdservice
    chown -R pds:pds /home/pds
    systemctl enable pdservice.service
    ;;
  *)
    echo "Usage: ./pdservice-install.sh -i"
    ;;
esac