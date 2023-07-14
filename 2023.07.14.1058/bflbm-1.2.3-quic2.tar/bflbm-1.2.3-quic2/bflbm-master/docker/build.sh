#!/bin/bash

die() { echo "$@" 1>&2 ; exit 1; }

id=`date +%s`_$BASHPID
pwd=`pwd`

docker build --network host -t $id docker || die "Failed to build docker image"
docker run --network host -v $pwd:/build --rm=true $id /build/docker/build-internal.sh || die "Failed to build module"
