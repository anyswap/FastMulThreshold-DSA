
#  Full parameter command :
# ./gsmpc-test.sh path port datadir keytype keystore1 passwdfile1 keystore2 passwdfile2

echo pwd: $(pwd)

#clean up
killall -9 gsmpctest bootnodetest
rm -rf $1/test/bin/gsmpctest
rm -rf $1/test/bin/bootnodetest
rm -rf $1/test/bin/gsmpc-client-test
rm -rf $1/test/log/*.log
rm -rf $1/test/nodedata/node*
rm -rf $1/test/nodekey/*.key
rm -rf test/reqaddr.sh
rm -rf test/sign.sh
#
sleep 3

cp -r $1/build/bin/gsmpc $1/test/bin/gsmpctest
cp -r $1/build/bin/bootnode $1/test/bin/bootnodetest
cp -r $1/build/bin/gsmpc-client $1/test/bin/gsmpc-client-test

rm -rf test/reqaddr.sh
rm -rf test/sign.sh

$(pwd)/bootnode-test.sh $1 &

sleep 40

path=$1/test/tmp/aaa
val=$(cat $path)
boot=`echo ${val%@*}`
boot2=`echo ${boot:0-128:128}`
echo bootnode key: $boot2

one=1
port=$2
port2=$(($2+$one))

datadir=
if [ ! $3 ]; then
  datadir=$1/test/nodedata
else
  datadir=$3
fi

kt=
if [ ! $4 ]; then
  kt=EC256K1
else
  kt=$4
fi

keyfile1=
if [ ! $5 ]; then
  keyfile1=$1/test/keystore/UTC--2018-10-11T01-26-58.462416324Z--3a1b3b81ed061581558a81f11d63e03129347437
else
  keyfile1=$5
fi

keyfile2=
if [ ! $7 ]; then
  keyfile2=$1/test/keystore/UTC--2019-03-11T08-42-59.809814178Z--a0f15f85b7a24b66f1d682b7244242093ec4430d
else
  keyfile2=$7
fi

pf1=
if [ ! $6 ]; then
  pf1=$1/test/passwdfile/passwdfile1
else
  pf1=$6
fi

pf2=
if [ ! $8 ]; then
  pf2=$1/test/passwdfile/passwdfile2
else
  pf2=$8
fi

gsmpc=$1/test/bin/gsmpctest
$gsmpc --rpcport $port --bootnodes "enode://$boot2@127.0.0.1:4440" --datadir $datadir/node1 --port 48541 --nodekey "$1/test/nodekey/node1.key" --waitmsg 100   --rotate 2  --maxage 72 --trytimes 1 --presignnum 3 --verbosity 5 --log $1/test/log/node1.log --nonetrestrict true --relay true &
sleep 2 

$gsmpc --rpcport $port2 --bootnodes "enode://$boot2@127.0.0.1:4440" --datadir $datadir/node2 --port 48542 --nodekey "$1/test/nodekey/node2.key" --waitmsg 100   --rotate 2  --maxage 72 --trytimes 1 --presignnum 3 --verbosity 5 --log $1/test/log/node2.log --nonetrestrict true --relay true &
sleep 2

echo
echo ======================= 
echo Every smpc node begin to generate 4 LARGE PRIME NUMBERS,it will take about 5 minutes.Please wait patiently!
echo ======================= 
echo

sleep 300

echo ====================== Generation of 4 LARGE PRIME NUMBERS completed ========================

$1/test/bin/gsmpc-client-test -cmd SetGroup -url http://127.0.0.1:$port -ts 2/2 -node http://127.0.0.1:$port -node http://127.0.0.1:$port2 > $1/test/tmp/bbb &
sleep 15

val=$(cat $1/test/tmp/bbb)
gid=`echo ${val:0-128:128}`
echo

$1/test/bin/gsmpc-client-test -cmd SetGroup -url http://127.0.0.1:$port -ts 2/2 -node http://127.0.0.1:$port -node http://127.0.0.1:$port2 > $1/test/tmp/ccc &
sleep 600 

val=$(cat $1/test/tmp/ccc)
subgid=`echo ${val:0-128:128}`
echo

$1/test/bin/gsmpc-client-test -cmd EnodeSig -url http://127.0.0.1:$port --keystore $keyfile1 --passwdfile $pf1 > $1/test/tmp/ddd1 &
sleep 10 

val=$(cat $1/test/tmp/ddd1)
#echo --------- val: $val ----------

#nodesig1=`echo ${val:0-284:284}`
tmps1="enode"
tmps2=`echo ${val##*enode}`
nodesig1=$tmps1$tmps2
#echo node1 enode sig: $nodesig1


$1/test/bin/gsmpc-client-test -cmd EnodeSig -url http://127.0.0.1:$port2 --keystore $keyfile2 --passwdfile $pf2 > $1/test/tmp/ddd2 &
sleep 10

val=$(cat $1/test/tmp/ddd2)
#echo --------- val: $val ----------

tmps1="enode"
tmps2=`echo ${val##*enode}`
nodesig2=$tmps1$tmps2
#echo node2 enode sig: $nodesig2
echo

echo ============================= Start to KeyGen ====================================
echo

$1/test/bin/gsmpc-client-test -cmd REQSMPCADDR --keystore $keyfile1 --passwdfile $pf1 -ts 2/2 --keytype $kt -gid $gid -mode 0 -url http://127.0.0.1:$port -sig $nodesig1 -sig $nodesig2 > $1/test/tmp/eee &
sleep 60

val=$(cat $1/test/tmp/eee)
val=`echo ${val##*=}`
key=`echo ${val:0:66}`

$1/test/bin/gsmpc-client-test -cmd ACCEPTREQADDR  -url http://127.0.0.1:$port --keystore $keyfile1 --passwdfile $pf1 -key $key &
sleep 3 

$1/test/bin/gsmpc-client-test -cmd ACCEPTREQADDR  -url http://127.0.0.1:$port2 --keystore $keyfile2 --passwdfile $pf2 -key $key &
sleep 3

sleep 240

touch test/reqaddr.sh
sleep 2
chmod a+x test/reqaddr.sh
sleep 2

a='curl -X POST -H "Content-Type":application/json --data '
b="'"
c='{"jsonrpc":"2.0","method":"smpc_getReqAddrStatus","params":["'
d="$key"
e='"],"id":67}'
f=" http://127.0.0.1:$port"
g=" > $1/test/tmp/fff &"

str=$a$b$c$d$e$b$f$g
echo $str | tee $1/test/reqaddr.sh
echo 

$1/test/reqaddr.sh &
sleep 20

kttmp=EC256K1
val=$(cat $1/test/tmp/fff)
val=`echo ${val##*PubKey}`
if [ "$kt" = "$kttmp" ];then
pubkey=`echo ${val:5:130}`
else
pubkey=`echo ${val:5:64}`
fi

echo
echo ================================== KeyGen successfully =======================================
echo
sleep 3

if [ "$kt" = "$kttmp" ];then
$1/test/bin/gsmpc-client-test -cmd PRESIGNDATA --keystore $keyfile1 --passwdfile $pf1 -pubkey $pubkey -subgid $subgid  -url  http://127.0.0.1:$port --keytype $kt &
sleep 100
fi

echo
echo ================================== Launch Pre-Sign finish =======================================
echo
sleep 1

echo keytype: $kt
echo keygen cmd key: $key
echo node1 keystore file: $keyfile1
echo node1 password file: $pf1
echo node2 keystore file: $keyfile2
echo node2 password file: $pf2
echo node1 datadir: $datadir/node1
echo node2 datadir: $datadir/node2
echo node1 rpc port: $port
echo node2 rpc port: $port2
echo gid: $gid
echo subgid: $subgid
echo pubkey: $pubkey

#rm -rf $1/test/tmp/ggg

#$1/test/bin/gsmpc-client-test -cmd SIGN --loop 1 --n 1 -ts 2/2 --keystore $keyfile1 --passwdfile $pf1 --keytype $kt --logfilepath $1/test/tmp/logfile -gid $subgid -mode 0 -url http://127.0.0.1:$port -pubkey $pubkey -msghash 0x90e032be062dd0dc689fa23df8c044936a2478cb602b292c7397354238a67d88  -msgcontext '{"swapInfo":{"swapid":"0x4f62545cdd05cc346c75bb42f685a18a02621e91512e0806eac528d0b2f6aa5f","swaptype":1,"bind":"0x0520e8e5e08169c4dbc1580dc9bf56638532773a","identifier":"ssUSDT2FSN"},"extra":{"ethExtra":{"gas":90000,"gasPrice":10000000000,"nonce":1}}}' > $1/test/tmp/ggg &
#sleep 60

#val=$(cat $1/test/tmp/ggg)
#val=`echo ${val##*keyID=}`
#signkey=`echo ${val:0:66}`
#echo
#echo -----------------------------------------sign cmd key : $signkey ----------------------------------------------

#rm -rf $1/test/tmp/hhh

#$1/test/bin/gsmpc-client-test -cmd ACCEPTSIGN  -url http://127.0.0.1:$port --keystore $keyfile1 --passwdfile $pf1 --key $signkey &
#sleep 3

#$1/test/bin/gsmpc-client-test  -cmd ACCEPTSIGN -url http://127.0.0.1:$port2 --keystore $keyfile2 --passwdfile $pf2 --key $signkey &
#sleep 3

#sleep 30

#touch test/sign.sh
#sleep 2
#chmod a+x test/sign.sh
#sleep 2

#a='curl -X POST -H "Content-Type":application/json --data '
#b="'"
#c='{"jsonrpc":"2.0","method":"smpc_getSignStatus","params":["'
#d="$signkey"
#e='"],"id":67}'
#f=" http://127.0.0.1:$port"
#g=" > $1/test/tmp/hhh &"

#str=$a$b$c$d$e$b$f$g
#echo $str | tee $1/test/sign.sh
#echo

#$1/test/sign.sh &
#sleep 30 

#val=$(cat $1/test/tmp/hhh)
#val=`echo ${val##*Rsv}`
#if [ "$kt" = "$kttmp" ];then
#rsv=`echo ${val:6:130}`
#else
#rsv=`echo ${val:6:64}`
#fi

#echo
#echo ----------------------------------------------- sign rsv : $rsv ---------------------------------------------

#killall -9 gsmpctest bootnodetest

#rm -rf $1/test/bin/gsmpctest
#rm -rf $1/test/bin/bootnodetest
#rm -rf $1/test/bin/gsmpc-client-test
#rm -rf $1/test/log/*.log
#rm -rf $1/test/nodedata/node*
#rm -rf $1/test/nodekey/*.key

#rm -rf test/reqaddr.sh
#rm -rf test/sign.sh


