#!/bin/bash
rsync -chavzP --stats --exclude .git --exclude build --exclude test root@loc:/srv/gopath/src/github.com/codingeasygo/pdservice/ `pwd`/
