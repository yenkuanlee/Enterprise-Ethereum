package main

import (
	"context"
	"crypto/ecdsa"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/bsostech/quorumgo/client"
)

func main() {
	bytecode := "0x0121b93f0000000000000000000000000000000000000000000000000000000000000002"
	data, _ := hexutil.Decode(bytecode)
	rpcClient, _ := rpc.Dial("http://localhost:20100")
	ethClient := ethclient.NewClient(rpcClient)
	privateKey, _ := crypto.HexToECDSA("8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63")
	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	gasLimit := uint64(3000000)
	nonce, _ := ethClient.PendingNonceAt(context.TODO(), fromAddress)
	var encryptedData []byte
	rpcClient.CallContext(context.TODO(), &encryptedData, "eth_getEncryptedHash", data)

	quorumtx := types.NewTransaction(nonce, common.HexToAddress("0xfeae27388a65ee984f452f86effed42aabd438fd"), nil, gasLimit, big.NewInt(0), encryptedData)

	signer := types.HomesteadSigner{}
	signedTx, _ := types.SignTx(quorumtx, signer, privateKey)
	args := &client.SendRawTxArgs{
		PrivateFor: []string{"mmQsRWMkSRWAzvIj6szVOADGlmStS1bSBBdKgpYXTS4="},
	}
	privateRawTransaction, _ := rlp.EncodeToBytes(signedTx)
	var txHash common.Hash
	rpcClient.CallContext(context.TODO(), &txHash, "eth_sendRawPrivateTransaction", hexutil.Encode(privateRawTransaction), args)
	log.Println(txHash.Hex())
}
