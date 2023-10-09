FROM alpine:latest
RUN HTTPS_PROXY=${HTTPS_PROXY} apk add --no-cache tzdata
ENV TZ Asia/Shanghai
RUN HTTPS_PROXY=${HTTPS_PROXY} apk add --no-cache ca-certificates
WORKDIR /app/
ADD conf /app/conf
ADD pdservice /usr/bin/pdservice
EXPOSE 9231
ENTRYPOINT ["pdservice"]
