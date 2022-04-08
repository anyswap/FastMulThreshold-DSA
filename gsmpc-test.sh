
#  Full parameter command :
# ./gsmpc-test.sh path port datadir keytype keyfile1 passwdfile1 keyfile2 passwdfile2 keyfile3 passwdfile3 keyfile4 passwdfile4 keyfile5 passwdfile5

echo ------------------------------------------------- pwd : $(pwd)   ------------------------------------------------
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
echo ------------------------------------------- bootnode key : $boot2 -----------------------------------------

one=1
two=2
three=3
four=4
port=$2
port2=$(($2+$one))
port3=$(($2+$two))
port4=$(($2+$three))
port5=$(($2+$four))

echo --------------------------------------- node1 rpc port : $port -------------------------------------------------------
echo --------------------------------------- node2 rpc port : $port2 ------------------------------------------------------
echo --------------------------------------- node3 rpc port : $port3 ------------------------------------------------------
echo --------------------------------------- node4 rpc port : $port4 ------------------------------------------------------
echo --------------------------------------- node5 rpc port : $port5 ------------------------------------------------------

datadir=
if [ ! $3 ]; then
  datadir=$1/test/nodedata
else
  datadir=$3
fi

echo ------------------------------------- datadir : $datadir ---------------------------------------------------------

kt=
if [ ! $4 ]; then
  kt=EC256K1
else
  kt=$4
fi

echo ------------------------------------- keytype : $kt ---------------------------------------------------------

keyfile1=
if [ ! $5 ]; then
  keyfile1=$1/test/keystore/UTC--2018-10-11T01-26-58.462416324Z--3a1b3b81ed061581558a81f11d63e03129347437
else
  keyfile1=$5
fi

echo ------------------------------------------ keyfile1 : $keyfile1 ------------------------------------------------

keyfile2=
if [ ! $7 ]; then
  keyfile2=$1/test/keystore/UTC--2019-03-11T08-42-59.809814178Z--a0f15f85b7a24b66f1d682b7244242093ec4430d
else
  keyfile2=$7
fi

echo ------------------------------------------ keyfile2 : $keyfile2 ----------------------------------------------------

keyfile3=
if [ ! $9 ]; then
  keyfile3=$1/test/keystore/UTC--2019-03-11T06-23-44.238608862Z--ecf880e334de65cd32a63b7b7567797ed707583b
else
  keyfile3=$9
fi

echo ------------------------------------------ keyfile3 : $keyfile3 ----------------------------------------------------

keyfile4=
if [ ! ${11} ]; then
  keyfile4=$1/test/keystore/UTC--2019-03-11T06-20-19.810771134Z--88525df23a7f1b3b549bcfd997ce8160ac7976a9
else
  keyfile4=${11}
fi

echo ------------------------------------------ keyfile4 : $keyfile4 ----------------------------------------------------

keyfile5=
if [ ! ${13} ]; then
  keyfile5=$1/test/keystore/UTC--2018-10-12T11-33-28.769681948Z--0963a18ea497b7724340fdfe4ff6e060d3f9e388
else
  keyfile5=${13}
fi

echo ------------------------------------------ keyfile5 : $keyfile5 ----------------------------------------------------

pf1=
if [ ! $6 ]; then
  pf1=$1/test/passwdfile/passwdfile1
else
  pf1=$6
fi

echo ------------------------------------------ password file1 : $pf1 ----------------------------------------------------

pf2=
if [ ! $8 ]; then
  pf2=$1/test/passwdfile/passwdfile2
else
  pf2=$8
fi

echo ------------------------------------------ password file2 : $pf2 ----------------------------------------------------

pf3=
if [ ! ${10} ]; then
  pf3=$1/test/passwdfile/passwdfile3
else
  pf3=${10}
fi

echo ------------------------------------------ password file3 : $pf3 ----------------------------------------------------

pf4=
if [ ! ${12} ]; then
  pf4=$1/test/passwdfile/passwdfile4
else
  pf4=${12}
fi

echo ------------------------------------------ password file4 : $pf4 ----------------------------------------------------

pf5=
if [ ! ${14} ]; then
  pf5=$1/test/passwdfile/passwdfile5
else
  pf5=${14}
fi

echo ------------------------------------------ password file5 : $pf5 ----------------------------------------------------
echo


echo -------------------------------------------------- begin to start 5 gsmpc nodes ----------------------------------------------------

gsmpc=$1/test/bin/gsmpctest
$gsmpc --rpcport $port --bootnodes "enode://$boot2@127.0.0.1:4440" --datadir $datadir/node1 --port 48541 --nodekey "$1/test/nodekey/node1.key" --waitmsg 100   --rotate 2  --maxage 72 --trytimes 1 --presignnum 3 2>&1 | tee $1/test/log/node1.log &
sleep 2 

$gsmpc --rpcport $port2 --bootnodes "enode://$boot2@127.0.0.1:4440" --datadir $datadir/node2 --port 48542 --nodekey "$1/test/nodekey/node2.key" --waitmsg 100   --rotate 2  --maxage 72 --trytimes 1 --presignnum 3 2>&1 | tee $1/test/log/node2.log &
sleep 2

$gsmpc --rpcport $port3 --bootnodes "enode://$boot2@127.0.0.1:4440" --datadir $datadir/node3 --port 48543 --nodekey "$1/test/nodekey/node3.key" --waitmsg 100   --rotate 2  --maxage 72 --trytimes 1 --presignnum 3 2>&1 | tee $1/test/log/node3.log &
sleep 2

$gsmpc --rpcport $port4 --bootnodes "enode://$boot2@127.0.0.1:4440" --datadir $datadir/node4 --port 48544 --nodekey "$1/test/nodekey/node4.key" --waitmsg 100   --rotate 2  --maxage 72 --trytimes 1 --presignnum 3 2>&1 | tee $1/test/log/node4.log &
sleep 2

$gsmpc --rpcport $port5 --bootnodes "enode://$boot2@127.0.0.1:4440" --datadir $datadir/node5 --port 48545 --nodekey "$1/test/nodekey/node5.key" --waitmsg 100   --rotate 2  --maxage 72 --trytimes 1 --presignnum 3 2>&1 | tee $1/test/log/node5.log &
sleep 12

echo ------------------------------------------------ 5 gsmpc nodes start finish --------------------------------------------------------------
echo 

echo ------------------------------- !!!every smpc node begin to generate 4 LARGE PRIME NUMBERS, this will take some time,it will take about 10 minutes, please BE PATIENT!!!  -----------------------------------------------
echo

sleep 500

echo -------------------------------------------------------------  Generation of 4 LARGE PRIME NUMBERS completed ------------------------------------------------------------------

$1/test/bin/gsmpc-client-test -cmd SetGroup -url http://127.0.0.1:$port -ts 3/5 -node http://127.0.0.1:$port -node http://127.0.0.1:$port2 -node http://127.0.0.1:$port3 -node http://127.0.0.1:$port4 -node http://127.0.0.1:$port5 > $1/test/tmp/bbb &
sleep 15

val=$(cat $1/test/tmp/bbb)
gid=`echo ${val:0-128:128}`
echo
echo --------------------------------------------------------- gid : $gid ---------------------------------------------------------------------------------

$1/test/bin/gsmpc-client-test -cmd SetGroup -url http://127.0.0.1:$port -ts 3/5 -node http://127.0.0.1:$port -node http://127.0.0.1:$port2 -node http://127.0.0.1:$port3 > $1/test/tmp/ccc &
sleep 15

val=$(cat $1/test/tmp/ccc)
subgid=`echo ${val:0-128:128}`
echo
echo ---------------------------------------------------------- subgid : $subgid ----------------------------------------------------------------------------


$1/test/bin/gsmpc-client-test -cmd EnodeSig -url http://127.0.0.1:$port --keystore $keyfile1 --passwdfile $pf1 > $1/test/tmp/ddd1 &
sleep 10 

val=$(cat $1/test/tmp/ddd1)
echo --------- val: $val ----------

#nodesig1=`echo ${val:0-284:284}`
tmps1="enode"
tmps2=`echo ${val##*enode}`
nodesig1=$tmps1$tmps2
echo ---------------------------------------- node sig 1 : $nodesig1 ------------------------------------------------------------------


$1/test/bin/gsmpc-client-test -cmd EnodeSig -url http://127.0.0.1:$port2 --keystore $keyfile2 --passwdfile $pf2 > $1/test/tmp/ddd2 &
sleep 10

val=$(cat $1/test/tmp/ddd2)
echo --------- val: $val ----------

tmps1="enode"
tmps2=`echo ${val##*enode}`
nodesig2=$tmps1$tmps2
echo ----------------------------------------- node sig 2 : $nodesig2 -------------------------------------------------------------------

$1/test/bin/gsmpc-client-test -cmd EnodeSig -url http://127.0.0.1:$port3 --keystore $keyfile3 --passwdfile $pf3 > $1/test/tmp/ddd3 &
sleep 10

val=$(cat $1/test/tmp/ddd3)
echo --------- val: $val ----------

tmps1="enode"
tmps2=`echo ${val##*enode}`
nodesig3=$tmps1$tmps2
echo ----------------------------------------- node sig 3 : $nodesig3 -------------------------------------------------------------------


$1/test/bin/gsmpc-client-test -cmd EnodeSig -url http://127.0.0.1:$port4 --keystore $keyfile4 --passwdfile $pf4 > $1/test/tmp/ddd4 &
sleep 10

val=$(cat $1/test/tmp/ddd4)
echo --------- val: $val ----------

tmps1="enode"
tmps2=`echo ${val##*enode}`
nodesig4=$tmps1$tmps2
echo ----------------------------------------- node sig 4 : $nodesig4 ---------------------------------------------------------------


$1/test/bin/gsmpc-client-test -cmd EnodeSig -url http://127.0.0.1:$port5 --keystore $keyfile5 --passwdfile $pf5 > $1/test/tmp/ddd5 &
sleep 10

val=$(cat $1/test/tmp/ddd5)
echo --------- val: $val ----------

tmps1="enode"
tmps2=`echo ${val##*enode}`
nodesig5=$tmps1$tmps2
echo ----------------------------------------- node sig 5 : $nodesig5 ------------------------------------------------------------------
echo

echo ------------------------------------------------------- begin to generate pubkey -----------------------------------------------------------------

$1/test/bin/gsmpc-client-test -cmd REQSMPCADDR --keystore $keyfile1 --passwdfile $pf1 -ts 3/5 --keytype $kt -gid $gid -mode 0 -url http://127.0.0.1:$port -sig $nodesig1 -sig $nodesig2 -sig $nodesig3 -sig $nodesig4 -sig $nodesig5 > $1/test/tmp/eee &
sleep 60

val=$(cat $1/test/tmp/eee)
val=`echo ${val##*=}`
key=`echo ${val:0:66}`
echo ----------------------------------------------------------- keygen cmd key : $key -----------------------------------------------------------------------------------

$1/test/bin/gsmpc-client-test -cmd ACCEPTREQADDR  -url http://127.0.0.1:$port --keystore $keyfile1 --passwdfile $pf1 -key $key &
sleep 3 

$1/test/bin/gsmpc-client-test -cmd ACCEPTREQADDR  -url http://127.0.0.1:$port2 --keystore $keyfile2 --passwdfile $pf2 -key $key &
sleep 3

$1/test/bin/gsmpc-client-test -cmd ACCEPTREQADDR  -url http://127.0.0.1:$port3 --keystore $keyfile3 --passwdfile $pf3 -key $key &
sleep 3

$1/test/bin/gsmpc-client-test -cmd ACCEPTREQADDR  -url http://127.0.0.1:$port4 --keystore $keyfile4 --passwdfile $pf4 -key $key &
sleep 3

$1/test/bin/gsmpc-client-test -cmd ACCEPTREQADDR  -url http://127.0.0.1:$port5 --keystore $keyfile5 --passwdfile $pf5 -key $key &
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
sleep 30

val=$(cat $1/test/tmp/fff)
val=`echo ${val##*PubKey}`
pubkey=`echo ${val:5:130}`
echo
echo ------------------------------------------------------------------ pubkey : $pubkey ------------------------------------------------------------

$1/test/bin/gsmpc-client-test -cmd PRESIGNDATA --keystore $keyfile1 --passwdfile $pf1 -pubkey $pubkey -subgid $subgid  -url  http://127.0.0.1:$port --keytype $kt &
sleep 20

rm -rf $1/test/tmp/ggg

$1/test/bin/gsmpc-client-test -cmd SIGN --loop 1 --n 1 -ts 3/5 --keystore $keyfile1 --passwdfile $pf1 --keytype $kt --logfilepath $1/test/tmp/logfile -gid $subgid -mode 0 -url http://127.0.0.1:$port -pubkey $pubkey -msghash 0x90e032be062dd0dc689fa23df8c044936a2478cb602b292c7397354238a67d88  -msgcontext '{"swapInfo":{"swapid":"0x4f62545cdd05cc346c75bb42f685a18a02621e91512e0806eac528d0b2f6aa5f","swaptype":1,"bind":"0x0520e8e5e08169c4dbc1580dc9bf56638532773a","identifier":"ssUSDT2FSN"},"extra":{"ethExtra":{"gas":90000,"gasPrice":10000000000,"nonce":1}}}' > $1/test/tmp/ggg &
sleep 60

val=$(cat $1/test/tmp/ggg)
val=`echo ${val##*keyID=}`
signkey=`echo ${val:0:66}`
echo
echo ------------------------------------------------------------------sign cmd key : $signkey ---------------------------------------------------------------------------

rm -rf $1/test/tmp/hhh

$1/test/bin/gsmpc-client-test -cmd ACCEPTSIGN  -url http://127.0.0.1:$port --keystore $keyfile1 --passwdfile $pf1 --key $signkey &
sleep 3

$1/test/bin/gsmpc-client-test  -cmd ACCEPTSIGN -url http://127.0.0.1:$port2 --keystore $keyfile2 --passwdfile $pf2 --key $signkey &
sleep 3

$1/test/bin/gsmpc-client-test  -cmd ACCEPTSIGN -url http://127.0.0.1:$port3 --keystore $keyfile3 --passwdfile $pf3 --key $signkey &
sleep 90

touch test/sign.sh
sleep 2
chmod a+x test/sign.sh
sleep 2

a='curl -X POST -H "Content-Type":application/json --data '
b="'"
c='{"jsonrpc":"2.0","method":"smpc_getSignStatus","params":["'
d="$signkey"
e='"],"id":67}'
f=" http://127.0.0.1:$port"
g=" > $1/test/tmp/hhh &"

str=$a$b$c$d$e$b$f$g
echo $str | tee $1/test/sign.sh
echo

$1/test/sign.sh &
sleep 20 

val=$(cat $1/test/tmp/hhh)
val=`echo ${val##*Rsv}`
rsv=`echo ${val:6:130}`
echo
echo ---------------------------------------------------------------------- sign rsv : $rsv --------------------------------------------------------------------------------

killall -9 gsmpctest bootnodetest

rm -rf $1/test/bin/gsmpctest
rm -rf $1/test/bin/bootnodetest
rm -rf $1/test/bin/gsmpc-client-test
#rm -rf $1/test/log/*.log
rm -rf $1/test/nodedata/node*
rm -rf $1/test/nodekey/*.key

rm -rf test/reqaddr.sh
rm -rf test/sign.sh


