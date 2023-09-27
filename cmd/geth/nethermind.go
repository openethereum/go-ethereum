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
	"math/big"
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
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/types"
	// "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	// "github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/ethdb"
	"github.com/ethereum/go-ethereum/internal/flags"
	"github.com/ethereum/go-ethereum/log"
	// "github.com/ethereum/go-ethereum/metrics"
	// "github.com/ethereum/go-ethereum/node"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/trie"
	"github.com/tecbot/gorocksdb"
	"github.com/urfave/cli/v2"
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

var headRoot = common.HexToHash("833490ba0cda8dc41d84e51fbd9a2debd0bbd6bf2647387b51be578236794e69")

func updateBalanceAndNonce(addr common.Address, simstatedb *state.StateDB, simtrie state.Trie, balancestr string, nonce uint64, slots map[common.Hash][]byte) {
	// if err != nil {
	// }

	// }

	// if err != nil {
	// }
	balance, _ := big.NewInt(0).SetString(balancestr, 10)
	simstatedb.SetBalance(addr, balance)
	simstatedb.SetNonce(addr, nonce)
	if slots != nil {
		for nr, val := range slots {
			simstatedb.SetState(addr, nr, common.BytesToHash(val))
		}
	}
}

func simulateNextBlock(chaindb ethdb.Database) {
	simstatedb, err := state.New(headRoot, state.NewDatabase(chaindb), nil)
	if err != nil {
		panic(err)
	}
	simtrie, err := simstatedb.Database().OpenTrie(headRoot)
	if err != nil {
		panic(err)
	}

	updateBalanceAndNonce(common.HexToAddress("0000000000000000000000000000000000000001"), simstatedb, simtrie, "38578639494568384886", 0, nil)
	updateBalanceAndNonce(common.HexToAddress("16f5c3dc347a5814b81553c7725d4ed9214c8a3c"), simstatedb, simtrie, "654791340401742673414", 91029, nil)
	updateBalanceAndNonce(common.HexToAddress("2458f163c231beaa673c903894060430cca101be"), simstatedb, simtrie, "295160057774628839", 3, nil)
	updateBalanceAndNonce(common.HexToAddress("6bbe78ee9e474842dbd4ab4987b3cefe88426a92"), simstatedb, simtrie, "17350471453192861357591", 1, nil)
	updateBalanceAndNonce(common.HexToAddress("a47dd92e07583011e2a13d0c8e1cc41133013844"), simstatedb, simtrie, "642954835302444968", 3104, nil)
	updateBalanceAndNonce(common.HexToAddress("c8a9a5b3517071f582b50b18633e522f6f4f38f5"), simstatedb, simtrie, "254707622817288156574", 93012, nil)
	updateBalanceAndNonce(common.HexToAddress("b840c9dbc0964bcd89d6410f34091b2cb6733adb"), simstatedb, simtrie, "0", 1, map[common.Hash][]byte{
		common.HexToHash("5291800258b0f2c8380e34854b9397c9b4f1bdf826bdf98f1ec487ed42c2241b"): common.Hex2Bytes("64000d98000000000000000000000000000000000000000068029640"),
		common.HexToHash("000000000000000000000000000000000000000000000000000000000000002b"): common.Hex2Bytes("6d520300009c5e0491866a1d2cbf826d5b09fae7b32c2ef9"),
		common.HexToHash("0000000000000000000000000000000000000000000000000000000000000005"): common.Hex2Bytes("01000100010001000100010036003600360036003400360036002b00360036"),
		common.HexToHash("0000000000000000000000000000000000000000000000000000000000000012"): common.Hex2Bytes("063cb71d504389a9"),
	})

	hash := simstatedb.IntermediateRoot(true)
	log.Info("computed simulated trie root", "root", hash)

	updateBalanceAndNonce(common.HexToAddress("16f5c3dc347a5814b81553c7725d4ed9214c8a3c"), simstatedb, simtrie, "654791808080606473414", 91028, nil)
	updateBalanceAndNonce(common.HexToAddress("2458f163c231beaa673c903894060430cca101be"), simstatedb, simtrie, "294479861409917609", 3, nil)
	updateBalanceAndNonce(common.HexToAddress("6bbe78ee9e474842dbd4ab4987b3cefe88426a92"), simstatedb, simtrie, "17350471453192859549953", 1, nil)
	updateBalanceAndNonce(common.HexToAddress("a47dd92e07583011e2a13d0c8e1cc41133013844"), simstatedb, simtrie, "643066021302963836", 3101, nil)
	updateBalanceAndNonce(common.HexToAddress("c8a9a5b3517071f582b50b18633e522f6f4f38f5"), simstatedb, simtrie, "254707724148790356574", 93011, nil)
	updateBalanceAndNonce(common.HexToAddress("b840c9dbc0964bcd89d6410f34091b2cb6733adb"), simstatedb, simtrie, "0", 1, map[common.Hash][]byte{
		// could be a delete, mais ça devrait pas faire de diff
		common.HexToHash("5291800258b0f2c8380e34854b9397c9b4f1bdf826bdf98f1ec487ed42c2241b"): common.Hex2Bytes("0000000000000000000000000000000000000000000000000000000000000000"),
		common.HexToHash("000000000000000000000000000000000000000000000000000000000000002b"): common.Hex2Bytes("00000000000000006d510300009c4a0191866a1d2cbf826d5b09fae7b32c2ef9"),
		common.HexToHash("0000000000000000000000000000000000000000000000000000000000000005"): common.Hex2Bytes("0001000100010001000100010035003500350035003300350035002b00350035"),
		common.HexToHash("0000000000000000000000000000000000000000000000000000000000000012"): common.Hex2Bytes("00000000000000000000000000000000000000000000000005caa43b0bc96959"),
	})

	hash = simstatedb.IntermediateRoot(true)
	log.Info("computed simulated trie initial root", "root", hash)
}
func importStateFromFile(db ethdb.Database) {
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
	if lastStorageRoot != (common.Hash{}) {
		log.Info("processing storage for last account")
		_, err := stTrie.Commit()
		if err != nil {
			panic(err)
		}
		if stTrie.Hash() != lastStorageRoot {
			fmt.Printf("invalid storage root %x != %x\n", stTrie.Hash(), lastStorageRoot)
		}
		stTrie = nil
	}
	h, err := accTrie.Commit()
	if err != nil {
		panic(err)
	}
	fmt.Println(h)
	if accTrie.Hash() != headRoot {
		panic("incorrect root hash")
	}
	log.Info("computed root hash=", accTrie.Hash())
	if err := batch.Write(); err != nil {
		panic(err)
	}
	/////////////////////////////////////////////////////////////

func rebuildSnapshot(db ethdb.Database) {
	// ////////////////// REBUILD SNAPSHOT //////////////////////
	_, err := snapshot.New(snapshot.Config{CacheSize: 2048}, db, trie.NewDatabase(db), headRoot)
	if err != nil {
		panic(err)
	}
	// if err := snaptree.Cap( /* headRoot */ accTrie.Hash(), 0); err != nil {
	// 	panic(err)
	// }
}
func nethermindImport(ctx *cli.Context) error {
	if ctx.Args().Len() < 2 {
		utils.Fatalf("This command requires two arguments.")
	}

	stack, _ := makeConfigNode(ctx)
	defer stack.Close()

	// chain, db := utils.MakeChain(ctx, stack, false)
	db := utils.MakeChainDatabase(ctx, stack, false)
	defer db.Close()
	triedb := trie.NewDatabase(db)
	core.SetupGenesisBlock(db, triedb, core.DefaultGnosisGenesisBlock())

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
	err := rlp.DecodeBytes(firstblockrlp, &firstblock)
	if err != nil {
		panic(err)
	}
	rawdb.WriteBlock(db, &firstblock)
	blockstoinsert := []string{
		// 26733404
		"f9077cf90207a0c24d7e70faad97677655e503c572fe25b531fd81f57dff154bea49f730d3d966a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347942ef7341f68e597e07eff4c171cdea1e409456baaa0c4b97cf1b45e589bcb2ea7f9a3877da75c0f7508986988bb41041d6c8609427ba08a414b0038c91fcaefe209154989ced42e5abacfee63e4fe7a4bc500cf9c7265a08d3535c52a6b1118b4e5bdbda3e9aaffda02b6b15ee03116c9b641cf7868336db90100040c820040000000400040000080000000000100400000000000004004000000000000000000000001000101000000000000400000000000000400000000081000000000000800000000000c400000000000140000000000000000200000000000000000020000000000000002000c0000000000000000000000011000400000000000200000000000000000000000001000000000000000000000000000200000010000040000000000400020000700400000000100004000000080400000000000080200040000000000000002800000400000000000000600000000002000000000001000000000000400000800501100000000000000000000000000000080840197eb5c8401c9c380830d15cb8464000aff8a4e65746865726d696e64a0b5c387928d62d69d55dc1aa6ef5d3564690f43d6aebd1fdba200682b14cb0e6188000000000000000007f9056eb8b602f8b36483019ae484b2d05e0084b2d05e008303f36b9422c1f6050e56d2876009903609a2cc3fef83b41580b844a140ae23000000000000000000000000000000000000000000000000000000000001a0bc000000000000000000000000acf4c2950107ef9b1c37faa1f9a866c8f0da88b9c001a06c7ed5902ad94dfeb119a4a60aa730cde3e9ef5231ca1fa70729b397e21c7adfa003743ea26b697d93ff11333c848f9b6c1e5faf00eeef8a8d46ebba6ea28a1e59f9026b1c84b2d05e008310ee3c94220675e77869cc716ad8afd00d445b3b813f632880b902046a76120200000000000000000000000029b9a7fbb8995b2423a71cc17cf9810798f6c54300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000018000000000000000000000000000000000000000000000000000000000000000043fbd653c00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000004150feac29ab0f1640236dec8deb2b5f35ef5a3d2588d34515087ae0562607c2b0157efdada2e480a45f81d200b31a867192883bf75c7a6b8323a6b9b62eb233421c0000000000000000000000000000000000000000000000000000000000000081eca00645c1a062726caab86ea0e6cd912168a88afac91863ea18a41ef9aa3694f223a00a65e3d155329a0646cd06d5b7e8bb3b66de06ab9ff6f7226c86d5d70e9a6da5b8b602f8b3648301cace84b2d05e0084b2d05e008303f36b9422c1f6050e56d2876009903609a2cc3fef83b41580b844a140ae23000000000000000000000000000000000000000000000000000000000001a2ae000000000000000000000000f9edb15a8965290b8cb32ef343fd6e6a169ecfd2c080a0f3bbb0eed1f0debe41d182b7dc1a9bf382269269ba99de3d85d7d41a838a6182a06b49f4ca4ced4f79505f017e2e84aa32259dac69325e4b7db06809f2b9df99bab8b602f8b3648301985f84b2d05e0084b2d05e008303f36b9422c1f6050e56d2876009903609a2cc3fef83b41580b844a140ae230000000000000000000000000000000000000000000000000000000000018b1e000000000000000000000000599abe13e88f1045e3aefe02a07f7bafc0c76b76c001a088a8970d4b0a52f0c5b9c91df608c133916ef71406b347aa2bd2b5d54373a484a05548f8dd74e89c929bf83d9c9522263343f847096a9a6a25240d72597184a54eb8d602f8d36483022dad8459682f008459682f0e8302b1669415287e573007d5fbd65d87ed46c62cf4c71dd66d80b8646f4d469b00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000b8b4e83d0f40c2a5a5e94e0c82d4a8d6f8b6dc4dc001a09e1f259e951cc5346595f1714ab158123ce1ce1d99f9240b4f4a3c23416c0fe9a008e007f2aea91efac66f4dbe5d6a128397ad5c26e553cc5c8d5c99c5648db421c0",
		// 26733530
		"f907aaf90207a083385865e98e4d73411c34bffc08334e275a0eedf97edfd8ea39b489d4673ec9a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940000000000000000000000000000000000000000a0833490ba0cda8dc41d84e51fbd9a2debd0bbd6bf2647387b51be578236794e69a0ef2daba1fedecaef2c2e45acd656732ff2ab2fe104572069f49c5c48705c944ea0706b02c59cd81d0bd3082cb1e72a4862188a69e2aea7836a6845c67f890fbb1eb901000000400000001004040000000000000400000000001000200000000000000000000010040004000000000000000200000000080000020000000000000020000000000000000000000000000900200000000000000140000000000000000000000000000022000000000000000000080000000008000000000000001000000000000000000000000000000000000000000000048000000000000000000000000003000000100000000000000000080000000020000200000000040000002000000000000200000000000000020000000400400000000000000000000000002000001000000000000000000000010000002000000000000000000000000080100080840197ebda8401c9c380830aca4d8464000d8e8a4e65746865726d696e64a00bab4ef0fe8d51bf489d154b5da2d8a79b57efad317803241174d2b48d89936b88000000000000000007f9059cb9013702f901336482133584d693a3f78501ad2747f7830ca2309430d155478ef27ab32a1d578be7b84bc5988af38180b8c45239af710000000000000000000000003f32bbca61d3e6eef9581d6f62a76a6820975b99000000000000000000000000000000000000000000000000000000001dcd650000000000000000000000000000000000000000000000000000000000000000140000000000000000000000000000000000000000000000000000000000000010cce9548241365051fbb73449a16270382481e3709ae50b905c8c81a6e66630550000000000000000000000000000000000000000000000000000000000000000c001a070f220f29369d2e71e401131f6fcbe6015fcc0791bde661b96b989d6842ce420a059b55e10149c58b3a985f6b414c3efab4597f0ab0c20d454219c61805371bd0af903ee83011af684b836d0408307a120949c1dc429a8d8f10c8eba522b608bc27f58d6abe280b90384c98075390000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000024000000000000000000000000000000000000000000000000000000000000002e0000101000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001a000000000000000000000008c17f7ba45f76e02cdfe3bf1c40c706000009c64050506030100080409070000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000000090000000000000000000000000000000000000000000000000000000000c2d2b00000000000000000000000000000000000000000000000000000000000c2dc8b0000000000000000000000000000000000000000000000000000000000c333450000000000000000000000000000000000000000000000000000000000c33f7c0000000000000000000000000000000000000000000000000000000000c361af0000000000000000000000000000000000000000000000000000000000c377100000000000000000000000000000000000000000000000000000000000c3bde60000000000000000000000000000000000000000000000000000000000c438ac0000000000000000000000000000000000000000000000000000000000c482040000000000000000000000000000000000000000000000000000000000000004bdfe3c32f4c2f6da4852e00a1eb985defb870e1f8ee9ad66de03e649b1a1a8fd7875e6ef3ce5af2baf3d55a7d34a31f56210da7be65499448434d0686c525f9976e02408375cda44c6fdecf7e20367721e096700cd2a104aa1ec663dd26a527fba89197f5d0a107e61056c57da6fb274b3e5126978796e73861454c82f77ca8b00000000000000000000000000000000000000000000000000000000000000045dd8d2d54a52b889279c09c517a83ee3ef50e3f80598c61c898dadcd43977b106bdcc592dd6f07355e789c51fd126d0cb24763a919aaddd411b119f98aea6d7d000e492b1b319f4c486648d58803d0c42f311477b693e6956730b2ed840f3aec1a2c6f12fce72cde888ef13c521d99ab5018103ae388d402ca5889c41a14ff7a81eca0069a1549020f270e06053cb5840a0c09e885056d9c643253f5eea0e587e54c06a07baaf265726d8f03812a4b69f4636e93fdf3418cd10c3600c2b0d2bc6411803df86f8320b5b884b2d05e008252089490ac227f61de41d5a27b1201da609f1374e2f4b888055441eb763a7f808081eca010c8252df2f4b150a9abcc9dbaa1a4e8c8aebd520c5823603f1985ee0be4e052a01b90ae3428bd5977fdb17ae9b30d1baa677b22431db8fb4e356daa9b175c7d4bc0",
		// 26733531
		"f90209f90204a0985fbf7e42f24f40cb5c8e74dc8df128f1ffb8bc3d5ee85392cdd78227cfe7a9a01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d49347940c36ac8863d0352436a70addbf1be34f3ea11017a0833490ba0cda8dc41d84e51fbd9a2debd0bbd6bf2647387b51be578236794e69a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b901000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080840197ebdb8401c9c380808464000d938a4e65746865726d696e64a004630c37f571827ddb23b79e4d5cb7e29c92288b4d53ea1b1fd077c3d33774c988000000000000000007c0c0",
	}
	for i, hexdata := range blockstoinsert {
		blockrlp := common.Hex2Bytes(hexdata)
		var block types.Block
		err = rlp.DecodeBytes(blockrlp, &block)
		if err != nil {
			panic(err)
		}
		rawdb.WriteBlock(db, &block)
		rawdb.WriteTd(db, block.Hash(), block.NumberU64(), block.Difficulty())
		// 	if i == latestBlock {
		// 		copy(headRoot[:], block.Root().Bytes())
		if i == len(blockstoinsert)-1 {
			rawdb.WriteHeadHeaderHash(db, block.Hash())
			rawdb.WriteHeadBlockHash(db, block.Hash())
			rawdb.WriteHeaderNumber(db, block.Hash(), block.NumberU64())
			rawdb.WriteCanonicalHash(db, block.Hash(), block.NumberU64())
			rawdb.WriteFinalizedBlockHash(db, block.Hash())
			rawdb.WriteHeadBlockHash(db, block.Hash())
			rawdb.WriteHeadFastBlockHash(db, block.Hash())
			fmt.Println("wrote head block", block.Hash())
		}
	}
	// 	}
	// }

	importStateFromFile(db)
	// simulateNextBlock(db)
	rebuildSnapshot(db)
	err = importCode(db, "/root/mainnet/execution-data/nethermind_db")
	if err != nil {
		panic(err)
	}
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
func importCode(db ethdb.KeyValueWriter, dbpath string) error {
	opts := gorocksdb.NewDefaultOptions()
	opts.SetCreateIfMissing(false)
	idbCode, err := gorocksdb.OpenDb(opts, dbpath+"/xdai/code")
	if err != nil {
		return fmt.Errorf("code import: error opening database", err)
	}
	ro := gorocksdb.NewDefaultReadOptions()
	codeIt := idbCode.NewIterator(ro)
	defer codeIt.Close()
	codeIt.SeekToFirst()
	if codeIt.Valid() {
		fmt.Println("codeIterator is valid")
	}
	for ; codeIt.Valid(); codeIt.Next() {
		// fmt.Printf("key=%x, value=%x\n", codeIt.Key().Data(), codeIt.Value().Data())
		rawdb.WriteCode(db, common.BytesToHash(codeIt.Key().Data()), codeIt.Value().Data())
	}
	return nil
}
