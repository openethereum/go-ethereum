// Copyright 2015 The go-ethereum Authors
// This file is part of go-ethereum.
//
// go-ethereum is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// go-ethereum is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with go-ethereum. If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"runtime"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/urfave/cli/v2"

	"github.com/tecbot/gorocksdb"
)

var (
	nethermindCommand = &cli.Command{
		Action:    nethermindImport,
		Name:      "nethermind",
		Usage:     "Import a Nethermind database",
		ArgsUsage: "<neth db path> <block hash>",
		Flags: flags.Merge([]cli.Flag{
			utils.CacheFlag,
			utils.SyncModeFlag,
			utils.GCModeFlag,
			utils.SnapshotFlag,
			utils.CacheDatabaseFlag,
			utils.CacheGCFlag,
			utils.MetricsEnabledFlag,
			utils.MetricsEnabledExpensiveFlag,
			utils.MetricsHTTPFlag,
			utils.MetricsPortFlag,
			utils.MetricsEnableInfluxDBFlag,
			utils.MetricsEnableInfluxDBV2Flag,
			utils.MetricsInfluxDBEndpointFlag,
			utils.MetricsInfluxDBDatabaseFlag,
			utils.MetricsInfluxDBUsernameFlag,
			utils.MetricsInfluxDBPasswordFlag,
			utils.MetricsInfluxDBTagsFlag,
			utils.MetricsInfluxDBTokenFlag,
			utils.MetricsInfluxDBBucketFlag,
			utils.MetricsInfluxDBOrganizationFlag,
			utils.TxLookupLimitFlag,
		}, utils.DatabasePathFlags),
		Description: `
The import command imports blocks from an RLP-encoded form. The form can be one file
with several RLP-encoded blocks, or several files can be used.

If only one file is used, import error will result in failure. If several files are used,
processing will proceed even if an individual RLP-file import failure occurs.`,
	}
)

func nethermindImport(ctx *cli.Context) error {
	if ctx.Args().Len() < 2 {
		utils.Fatalf("This command requires two arguments.")
	}
	// // Start metrics export if enabled
	// utils.SetupMetrics(ctx)
	// // Start system runtime metrics collection
	// go metrics.CollectProcessMetrics(3 * time.Second)

	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	chain, db := utils.MakeChain(ctx, stack, false)
	defer db.Close()

	// Start periodically gathering memory profiles
	// var peakMemAlloc, peakMemSys uint64
	// go func() {
	// 	stats := new(runtime.MemStats)
	// 	for {
	// 		runtime.ReadMemStats(stats)
	// 		if atomic.LoadUint64(&peakMemAlloc) < stats.Alloc {
	// 			atomic.StoreUint64(&peakMemAlloc, stats.Alloc)
	// 		}
	// 		if atomic.LoadUint64(&peakMemSys) < stats.Sys {
	// 			atomic.StoreUint64(&peakMemSys, stats.Sys)
	// 		}
	// 		time.Sleep(5 * time.Second)
	// 	}
	// }()
	// Import the chain
	start := time.Now()

	// Connect to the Ethereum node over RPC// Connect to the Ethereum node over RPC
	client, err := ethclient.Dial("https://localhost:8545")
	if err != nil {
		log.Crit("Failed to connect to the Ethereum node: %v", err)
	}

	// Get the latest block number
	latestBlock, err := client.BlockNumber(context.Background())
	if err != nil {
		log.Crit("Failed to get latest block number: %v", err)
	}

	// Create a LevelDB database for storing the RLP of the blocks
	// dbPath := filepath.Join(".", "blocksdb")
	// os.MkdirAll(dbPath, os.ModePerm)
	// db, err := rawdb.NewLevelDBDatabase(dbPath, 0, 0, "")
	// if err != nil {
	// 	log.Fatalf("Failed to create LevelDB database: %v", err)
	// }

	// Iterate over all the blocks since the genesis and insert their RLP in the database
	var headRoot common.Hash
	for i := uint64(0); i <= latestBlock; i++ {
		block, err := client.BlockByNumber(context.Background(), new(big.Int).SetUint64(i))
		if err != nil {
			log.Crit("Failed to get block", "number", i, "error", err)
		}

		// Encode the block as RLP
		blockBytes, err := rlp.EncodeToBytes(block)
		if err != nil {
			log.Crit("Failed to RLP-encode block", "number", i, "error", err)
		}

		// Insert the RLP of the block in the LevelDB database
		rawdb.WriteCanonicalBlock(db, blockBytes, block.NumberU64())

		if i == latestBlock {
			copy(headRoot[:], block.Root().Bytes())
		}
	}

	// Import snapshot

	// Get the snapshot to reconstruct the trie from it
	snaptree, err := snapshot.New(snapshot.Config{}, db, db, headRoot)
	if err != nil {
		panic(err)
	}

	// regenerate the trie from it
	if err := snapshot.GenerateTrie(snaptree, headRoot, db, stateBloom); err != nil {
		panic(err)
	}

	// var importErr error
	opts := gorocksdb.NewDefaultOptions()
	opts.SetCreateIfMissing(false)

	idbHeaders, err := gorocksdb.Open(opts, ctx.Args().First()+"/xdai/headers")
	if err != nil {
		panic(err)
	}
	roh := gorocksdb.NewDefaultReadOptions()
	defer roh.Close()

	header, err := db.Get(roh, ctx.Args().Slice()[1])
	if err != nil {
		panic(err)
	}

	var h types.Header
	err = rlp.DecodeBytes(header[:], &h)
	if err != nil {
		panic(err)
	}

	idbNode, err := gorocksdb.Open(opts, ctx.Args().First()+"/xdai/state/0")
	if err != nil {
		panic(err)
	}
	// TODO check idbNode shouldn't be freed somehow
	ror := gorocksdb.NewDefaultReadOptions()
	defer ror.Close()

	rootNode, err := db.Get(ror, h.Root[:])
	if err != nil {
		panic(err)
	}
	var root [17]common.Hash
	err = rlp.DecodeBytes(rootNode, &root)
	if err != nil {
		panic(err)
	}
	// fonction recursive qui va chercher les enfants et les balance dans la DB
	// db.NewBatch().Put(...)

	// if ctx.Args().Len() == 1 {
	// 	if err := utils.ImportChain(chain, ctx.Args().First()); err != nil {
	// 		importErr = err
	// 		log.Error("Import error", "err", err)
	// 	}
	// } else {
	// 	for _, arg := range ctx.Args().Slice() {
	// 		if err := utils.ImportChain(chain, arg); err != nil {
	// 			importErr = err
	// 			log.Error("Import error", "file", arg, "err", err)
	// 		}
	// 	}
	// }
	chain.Stop()
	fmt.Printf("Import done in %v.\n\n", time.Since(start))

	// Output pre-compaction stats mostly to see the import trashing
	// showLeveldbStats(db)

	// Print the memory statistics used by the importing
	// mem := new(runtime.MemStats)
	// runtime.ReadMemStats(mem)

	// fmt.Printf("Object memory: %.3f MB current, %.3f MB peak\n", float64(mem.Alloc)/1024/1024, float64(atomic.LoadUint64(&peakMemAlloc))/1024/1024)
	// fmt.Printf("System memory: %.3f MB current, %.3f MB peak\n", float64(mem.Sys)/1024/1024, float64(atomic.LoadUint64(&peakMemSys))/1024/1024)
	// fmt.Printf("Allocations:   %.3f million\n", float64(mem.Mallocs)/1000000)
	// fmt.Printf("GC pause:      %v\n\n", time.Duration(mem.PauseTotalNs))

	// if ctx.Bool(utils.NoCompactionFlag.Name) {
	// 	return nil
	// }

	// // Compact the entire database to more accurately measure disk io and print the stats
	// start = time.Now()
	// fmt.Println("Compacting entire database...")
	// if err := db.Compact(nil, nil); err != nil {
	// 	utils.Fatalf("Compaction failed: %v", err)
	// }
	// fmt.Printf("Compaction done in %v.\n\n", time.Since(start))

	// showLeveldbStats(db)
	// return importErr
}