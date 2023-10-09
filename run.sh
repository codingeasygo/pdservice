#!/bin/bash
go build -v .
PD_HOST_SUFFIX=.test.loc PD_MATCH_KEY=$1 ./pdservice
