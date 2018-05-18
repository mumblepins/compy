#!/bin/sh -x

ARGS="-brotli 7 -jpeg 35 -minify"
if [ -e /etc/compy/ca.crt ] && [ -e /etc/compy/ca.key ]; then
        echo "Using Mitm with /etc/compy/ca.crt"
        ARGS="$ARGS -ca /etc/compy/ca.crt -cakey /etc/compy/ca.key"
fi

exec /usr/local/bin/compy $ARGS



