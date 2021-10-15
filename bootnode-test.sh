

cmd=$1/test/bin/bootnodetest
$cmd --genkey=$1/test/tmp/boot.key &
sleep 10
$cmd --nodekey=$1/test/tmp/boot.key > $1/test/tmp/aaa &
sleep 10

