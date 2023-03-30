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
	// "context"
	// "encoding/json"
	// "errors"
	"fmt"
	// "math/big"
	"os"
	// "runtime"
	// "strconv"
	// "sync/atomic"
	"bufio"
	"encoding/hex"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/cmd/utils"
	"github.com/ethereum/go-ethereum/common"
	// "github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	// "github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	// "github.com/ethereum/go-ethereum/core/types"
	// "github.com/ethereum/go-ethereum/crypto"
	// "github.com/ethereum/go-ethereum/ethclient"
	// "github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/log"
	// "github.com/ethereum/go-ethereum/metrics"
	// "github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/urfave/cli/v2"
	// "github.com/tecbot/gorocksdb"
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

	// chain, db := utils.MakeChain(ctx, stack, false)
	db := utils.MakeChainDatabase(ctx, stack, false)
	triedb := trie.NewDatabase(db)
	core.SetupGenesisBlock(db, triedb, core.DefaultGnosisGenesisBlock())
	// defer db.Close()

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
	// client, err := ethclient.Dial("https://localhost:8545")
	// if err != nil {
	// 	log.Crit("Failed to connect to the Ethereum node: %v", err)
	// }

	// Get the latest block number
	// latestBlock, err := client.BlockNumber(context.Background())
	// if err != nil {
	// 	log.Crit("Failed to get latest block number: %v", err)
	// }

	// Create a LevelDB database for storing the RLP of the blocks
	// dbPath := filepath.Join(".", "blocksdb")
	// os.MkdirAll(dbPath, os.ModePerm)
	// db, err := rawdb.NewLevelDBDatabase(dbPath, 0, 0, "")
	// if err != nil {
	// 	log.Fatalf("Failed to create LevelDB database: %v", err)
	// }

	// Iterate over all the blocks since the genesis and insert their RLP in the database
	// var headRoot common.Hash
	// for i := uint64(0); i <= latestBlock; i++ {
	// 	block, err := client.BlockByNumber(context.Background(), new(big.Int).SetUint64(i))
	// 	if err != nil {
	// 		log.Crit("Failed to get block", "number", i, "error", err)
	// 	}

	// 	// Insert the RLP of the block in the LevelDB database
	// 	rawdb.WriteBlock(db, block)
	var firstblock types.Block
	firstblockrlp := common.Hex2Bytes("f90246f90241a04f1dd23188aab3a76b463e4af801b52b1248ef073c648cbdc4c9333d3da79756a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d4934794cace5b3c29211740e595850e80478416ee77ca21a040cf4430ecaa733787d1a65154a3b9efb560c95d9e324a23b97f0609b539133ba056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000090ffffffffffffffffffffffffeda7455a018398968080845bbba5399fde830201018f5061726974792d457468657265756d86312e32392e30826c69841258baa5b841c35e9f8ac05c69d8c36af2cb8b7bb3beda5945e8367fec758c459d32f9ddc183206bad888ebd7addaa6e3f00593100a628c5e86ca80ebe48d4fc831dd36f825d01c0c0")
	fmt.Println(firstblockrlp)
	err := rlp.DecodeBytes(firstblockrlp, &firstblock)
	if err != nil {
		panic(err)
	}
	fmt.Println(firstblock.NumberU64())
	rawdb.WriteBlock(db, &firstblock)

	blockrlp := common.Hex2Bytes("f90209f90204a0985fbf7e42f24f40cb5c8e74dc8df128f1ffb8bc3d5ee85392cdd78227cfe7a9a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940c36ac8863d0352436a70addbf1be34f3ea11017a0833490ba0cda8dc41d84e51fbd9a2debd0bbd6bf2647387b51be578236794e69a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080840197ebdb8401c9c380808464000d938a4e65746865726d696e64a004630c37f571827ddb23b79e4d5cb7e29c92288b4d53ea1b1fd077c3d33774c988000000000000000007c0c0")
	var block types.Block
	fmt.Println(blockrlp)
	err = rlp.DecodeBytes(blockrlp, &block)
	if err != nil {
		panic(err)
	}
	// 	if i == latestBlock {
	// 		copy(headRoot[:], block.Root().Bytes())
	rawdb.WriteHeadHeaderHash(db, block.Hash())
	rawdb.WriteHeadBlockHash(db, block.Hash())
	rawdb.WriteBlock(db, &block)
	rawdb.WriteHeaderNumber(db, block.Hash(), block.NumberU64())
	rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
	rawdb.WriteFinalizedBlockHash(db, block.Hash())
	rawdb.WriteHeadBlockHash(db, block.Hash())
	rawdb.WriteHeadFastBlockHash(db, block.Hash())
	fmt.Println("wrote head block", block.Hash())
	// 	}
	// }

	///// LECTURE DU FICHIER /////////////////////////////////////////
	// Import snapshot from file
	batch := db.NewBatch()
	inputFile, err := os.Open("state.txt")
	if err != nil {
		panic(err)
	}
	defer inputFile.Close()

	// Create a scanner to read the input file line by line
	scanner := bufio.NewScanner(inputFile)

	var (
		// 	lastAccountHash common.Hash
		lastStorageRoot common.Hash
		count           uint64
		stTrie          *trie.StackTrie
		savenode        = func(owner common.Hash, path []byte, hash common.Hash, blob []byte) {
			rawdb.WriteTrieNode(batch, hash, blob)
		}
		accTrie = trie.NewStackTrie(savenode)
		// headRoot = common.HexToHash("833490ba0cda8dc41d84e51fbd9a2debd0bbd6bf2647387b51be578236794e69")
	)

	// Read each line and process the hex values
	for scanner.Scan() {
		line := scanner.Text()
		hexValues := strings.Split(line, ":")
		if len(hexValues) != 3 {
			fmt.Printf("Invalid line format: %s\n", line)
			continue
		}

		// Convert each hex value to its []byte representation
		var byteValues [][]byte
		for _, hexValue := range hexValues {
			byteValue, err := hex.DecodeString(hexValue)
			if err != nil {
				fmt.Printf("Invalid hex value: %s\n", hexValue)
				continue
			}
			byteValues = append(byteValues, byteValue)
		}

		// is this part of the account tree ?
		if hexValues[0] == "833490ba0cda8dc41d84e51fbd9a2debd0bbd6bf2647387b51be578236794e69" {
			// new account, verifies that the storage of the previous account
			// account is in agreement.
			if lastStorageRoot != (common.Hash{}) {
				_, err := stTrie.Commit()
				if err != nil {
					panic(err)
				}
				if stTrie.Hash() != lastStorageRoot {
					fmt.Printf("invalid storage root %x != %x\n", stTrie.Hash(), lastStorageRoot)
					panic("ici")
				}
				// if count > 1000000 {
				// 	break
				// }
				lastStorageRoot = common.Hash{}
				stTrie = nil
			}
			err = accTrie.TryUpdate(byteValues[1], byteValues[2])
			if err != nil {
				panic(err)
			}
			var account types.StateAccount
			rlp.DecodeBytes(byteValues[2], &account)

			if account.Root != emptyRoot {
				stTrie = trie.NewStackTrie(savenode)
				lastStorageRoot = account.Root
			}
			// 		accountHash := common.BytesToHash(byteValues[1])
			// 		rawdb.WriteAccountSnapshot(batch, accountHash, snapshot.SlimAccountRLP(account.Nonce, account.Balance, account.Root, account.CodeHash))
			// 		lastAccountHash = accountHash

		} else {
			err = stTrie.TryUpdate(byteValues[1], byteValues[2])
			if err != nil {
				panic(err)
			}
			// 		storageHash := common.BytesToHash(byteValues[0])
			// 		rawdb.WriteStorageSnapshot(batch, lastAccountHash, storageHash, byteValues[2])
		}
		count++
		if count%1000000 == 0 {
			log.Info("Processing", "line count", count)
			if err := batch.Write(); err != nil {
				panic(err)
			}
			batch = db.NewBatch()
		}
	}
	h, err := accTrie.Commit()
	if err != nil {
		panic(err)
	}
	fmt.Println(h)
	// if accTrie.Hash() != headRoot {
	// 	panic("incorrect root hash")
	// }
	if err := batch.Write(); err != nil {
		panic(err)
	}
	/////////////////////////////////////////////////////////////

	// ////////////////// REBUILD SNAPSHOT //////////////////////
	_, err = snapshot.New(snapshot.Config{CacheSize: 2048}, db, trie.NewDatabase(db) /* headRoot */, accTrie.Hash())
	if err != nil {
		panic(err)
	}
	// if err := snaptree.Cap( /* headRoot */ accTrie.Hash(), 0); err != nil {
	// 	panic(err)
	// }
	db.Close()
	/////////////////////////////////////////////////////////////

	fmt.Println("redemarre la chaine")
	chain, db := utils.MakeChain(ctx, stack, false)
	chain.Stop()
	db.Close()

	// regenerate the trie from it
	// stateBloom, err := pruner.NewStateBloomWithSize(2048)
	// if err != nil {
	// 	return err
	// }
	// if err := snapshot.GenerateTrie(snaptree, headRoot, db, stateBloom); err != nil {
	// 	panic(err)
	// }

	// // var importErr error
	// opts := gorocksdb.NewDefaultOptions()
	// opts.SetCreateIfMissing(false)

	// idbHeaders, err := gorocksdb.Open(opts, ctx.Args().First()+"/xdai/headers")
	// if err != nil {
	// 	panic(err)
	// }
	// roh := gorocksdb.NewDefaultReadOptions()
	// defer roh.Close()

	// header, err := db.Get(roh, ctx.Args().Slice()[1])
	// if err != nil {
	// 	panic(err)
	// }

	// var h types.Header
	// err = rlp.DecodeBytes(header[:], &h)
	// if err != nil {
	// 	panic(err)
	// }

	// idbNode, err := gorocksdb.Open(opts, ctx.Args().First()+"/xdai/state/0")
	// if err != nil {
	// 	panic(err)
	// }
	// // TODO check idbNode shouldn't be freed somehow
	// ror := gorocksdb.NewDefaultReadOptions()
	// defer ror.Close()

	// rootNode, err := db.Get(ror, h.Root[:])
	// if err != nil {
	// 	panic(err)
	// }
	// var root [17]common.Hash
	// err = rlp.DecodeBytes(rootNode, &root)
	// if err != nil {
	// 	panic(err)
	// }

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
	// chain.Stop()
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
	return nil
}