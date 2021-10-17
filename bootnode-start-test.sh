
cp -r $1/bin/cmd/bootnode $1/test/bin/bootnodetest
cmd=$1/test/bin/bootnodetest
$cmd --genkey=$1/test/tmp/boot.key &
sleep 5 
$cmd --nodekey=$1/test/tmp/boot.key > $1/test/tmp/aaa &
sleep 10

