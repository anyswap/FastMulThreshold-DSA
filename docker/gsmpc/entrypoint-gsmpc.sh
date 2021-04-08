#!/bin/bash

set -e

BASEDIR=/gsmpc
CONFDIR=$BASEDIR/conf
DATADIR=$BASEDIR/data
LOGDIR=$BASEDIR/log

mkdir -p -m 750 $CONFDIR $DATADIR $LOGDIR
chmod -R o-rwx $CONFDIR $DATADIR $LOGDIR

touch $LOGDIR/gsmpc.log
chmod 640 $LOGDIR/gsmpc.log

exec gsmpc --nodekey $CONFDIR/node.key --datadir $DATADIR --log $LOGDIR/gsmpc.log $@
