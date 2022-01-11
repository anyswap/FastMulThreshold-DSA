package utils

import (
	//"crypto/ecdsa"
	//"fmt"
	//"io"
	//"io/ioutil"
	//"math/big"
	//"os"
	//"path/filepath"
	//"strconv"
	//"strings"
	//"text/tabwriter"
	//"text/template"
	//"time"

	//"github.com/anyswap/FastMulThreshold-DSA/accounts"
	//"github.com/anyswap/FastMulThreshold-DSA/accounts/keystore"
	//"github.com/anyswap/FastMulThreshold-DSA/common"
	//"github.com/anyswap/FastMulThreshold-DSA/common/fdlimit"
	//"github.com/anyswap/FastMulThreshold-DSA/consensus"
	//"github.com/anyswap/FastMulThreshold-DSA/consensus/clique"
	//"github.com/anyswap/FastMulThreshold-DSA/consensus/ethash"
	//"github.com/anyswap/FastMulThreshold-DSA/core"
	//"github.com/anyswap/FastMulThreshold-DSA/core/rawdb"
	//"github.com/anyswap/FastMulThreshold-DSA/core/vm"
	//"github.com/anyswap/FastMulThreshold-DSA/crypto"
	//"github.com/anyswap/FastMulThreshold-DSA/eth"
	//"github.com/anyswap/FastMulThreshold-DSA/eth/downloader"
	//"github.com/anyswap/FastMulThreshold-DSA/eth/gasprice"
	//"github.com/anyswap/FastMulThreshold-DSA/ethdb"
	//"github.com/anyswap/FastMulThreshold-DSA/ethstats"
	//"github.com/anyswap/FastMulThreshold-DSA/graphql"
	//"github.com/anyswap/FastMulThreshold-DSA/internal/ethapi"
	//"github.com/anyswap/FastMulThreshold-DSA/internal/flags"
	//"github.com/anyswap/FastMulThreshold-DSA/les"
	//"github.com/anyswap/FastMulThreshold-DSA/log"
	//"github.com/anyswap/FastMulThreshold-DSA/metrics"
	//"github.com/anyswap/FastMulThreshold-DSA/metrics/exp"
	//"github.com/anyswap/FastMulThreshold-DSA/metrics/influxdb"
	//"github.com/anyswap/FastMulThreshold-DSA/miner"
	//"github.com/anyswap/FastMulThreshold-DSA/node"
	//"github.com/anyswap/FastMulThreshold-DSA/p2p"
	//"github.com/anyswap/FastMulThreshold-DSA/p2p/discv5"
	//"github.com/anyswap/FastMulThreshold-DSA/p2p/enode"
	//"github.com/anyswap/FastMulThreshold-DSA/p2p/nat"
	//"github.com/anyswap/FastMulThreshold-DSA/p2p/netutil"
	//"github.com/anyswap/FastMulThreshold-DSA/params"
	//pcsclite "github.com/gballet/go-libpcsclite"
	cli "gopkg.in/urfave/cli.v1"
)

// MigrateFlags sets the global flag from a local flag when it's set.
// This is a temporary function used for migrating old command/flags to the
// new format.
//
// e.g. geth account new --keystore /tmp/mykeystore --lightkdf
//
// is equivalent after calling this method with:
//
// geth --keystore /tmp/mykeystore --lightkdf account new
//
// This allows the use of the existing configuration functionality.
// When all flags are migrated this function can be removed and the existing
// configuration functionality must be changed that is uses local flags
func MigrateFlags(action func(ctx *cli.Context) error) func(*cli.Context) error {
	return func(ctx *cli.Context) error {
		for _, name := range ctx.FlagNames() {
			if ctx.IsSet(name) {
			    err := ctx.GlobalSet(name, ctx.String(name))
			    if err != nil {
				return err
			    }
			}
		}
		return action(ctx)
	}
}
