

cmd=$1/test/bin/bootnodetest
echo $cmd

$cmd --genkey=$1/test/boot.key
$cmd --nodekey=$1/test/boot.key > $1/test/aaa

