#!/bin/bash
addr=`docker inspect --format="{{.NetworkSettings.IPAddress}}" docker-discover`
echo docker_cert=../test/certs/client
echo docker_addr=tcp://$addr:2376
echo docker_host=$addr
