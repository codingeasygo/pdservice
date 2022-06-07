#!/bin/bash
rsync -chavzP --stats --exclude build --exclude test root@loc:/srv/gopath/src/github.com/codingeasygo/pdservice/ `pwd`/
