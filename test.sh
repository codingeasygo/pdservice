
docker rm -f pdservice
docker run --name pdservice -v /var/run/docker.sock:/var/run/docker.sock -e PD_DOCKER_HOST=172.17.0.1 -e PD_HOST_SUFFIX=.test.loc -e PD_MATCH_KEY=$2 -p 9231:9231 -d pdservice:$1
