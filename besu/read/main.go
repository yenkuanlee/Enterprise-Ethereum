package main

import (
	"context"
	"log"
	"strings"

	"github.com/bsostech/go-besu/privacy"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
)

const contractAbi = "[{\"constant\":false,\"inputs\":[{\"name\":\"proposal\",\"type\":\"uint256\"}],\"name\":\"vote\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"proposals\",\"outputs\":[{\"name\":\"name\",\"type\":\"bytes32\"},{\"name\":\"voteCount\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"chairperson\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"to\",\"type\":\"address\"}],\"name\":\"delegate\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"winningProposal\",\"outputs\":[{\"name\":\"winningProposal_\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"voter\",\"type\":\"address\"}],\"name\":\"giveRightToVote\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"voters\",\"outputs\":[{\"name\":\"weight\",\"type\":\"uint256\"},{\"name\":\"voted\",\"type\":\"bool\"},{\"name\":\"delegate\",\"type\":\"address\"},{\"name\":\"vote\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"winnerName\",\"outputs\":[{\"name\":\"winnerName_\",\"type\":\"bytes32\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"proposalNames\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"

func main() {
	privateFromString := "A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo="
	privateFor1String := "Ko2bVqD+nNlNYL5EE7y3IdOnviftjiizpjRt+HTuFBs="
	privateFor2String := "k2zXEin4Ip/qBGlRkJejnGWdP9cjkK+DAvKNW31L2C8="
	privateFrom, _ := privacy.ToPublicKey(privateFromString)
	privateFor1, _ := privacy.ToPublicKey(privateFor1String)
	privateFor2, _ := privacy.ToPublicKey(privateFor2String)
	participants := []*privacy.PublicKey{&privateFrom, &privateFor1, &privateFor2}

	rpcClient, _ := rpc.Dial("http://18.179.178.141:20000")
	priv := privacy.NewPrivacy(rpcClient)
	rootPrivacyGroup := priv.FindRootPrivacyGroup(participants)
	parsedABI, _ := abi.JSON(strings.NewReader(contractAbi))

	contractAddress := common.HexToAddress("0xaa56458ec6440e480f38be8de3a1abca3a95b7ea")
	winner, _ := parsedABI.Pack("winnerName")
	msg := map[string]interface{}{
		"to":   contractAddress,
		"data": hexutil.Bytes(winner),
	}
	var result interface{}
	rpcClient.CallContext(context.TODO(), &result, "priv_call", rootPrivacyGroup.ID, msg, "latest")
	output, _ := hexutil.Decode(result.(string))
	log.Println(string(output))
}
