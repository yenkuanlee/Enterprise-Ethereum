# Enterprise-Ethereum Demo
###### tags: `Document`

## Abstract
- Ethereum
    - Ethereum 中透過交易 (transaction) 與區塊鏈溝通
    - Ethereum 提供智能合約 (smart contract)，將程式功能 (function) 運行在區塊鏈節點上，可將功能分為三大類：
        1. deploy
        2. write
        3. read
    - Deploy 與 write 的 function 執行會改變區塊鏈狀態，等同於一筆交易，在 Ethereum 上需支付手續費 (gas)。
    - Read function 從區塊鏈上查詢，不需手續費。
    - ==本文將 Demo Ethereum 交易與智能合約操作流程==
- Enterprise-Ethereum (EE)
    - 企業以太坊，聯盟鏈，須遵守 [EEA 規範](https://entethalliance.github.io/client-spec/spec.html#sec-private-transactions)。
        - 可想像聯盟鏈中每個節點代表一家企業，目的是解決企業間的信任問題。
    - EE 與 Ethereum 大致相同，一樣有交易和智能合約。EE 多了隱私 (privacy) 與聯盟治理 (permission) 兩大模組，並提供可抽換的共識機制。
    - 本文著重兩大 EE：
        - [Quorum](https://github.com/jpmorganchase/quorum)
        - [Hyperledger Besu](https://github.com/hyperledger/besu)
    - 私交易 (private transaction) 是聯盟鏈中最重要的功能，==本文將 Demo Quorum 與 Besu 的私交易，進而操作私密智能合約 (private smart contract)。==
- BSOS 做了什麼？

## Outline
- Ethereum Transaction
    - Transaction Model of [go-ethereum](https://github.com/ethereum/go-ethereum)
    - Make an Ethereum Transaction
        - Introduction
        - [Metamask](https://metamask.io/)
        - [Go Ethereum Book](https://goethereumbook.org/en/)
    - Ethereum Smart Contract
        - Deploy Smart Contract by Transaction
        - Write Smart Contract by Transaction
        - Read Smart Contract by RPC call
- Enterprise Ethereum Demo
    - Demo Envirement
        - Quorum
        - Besu
    - Private Transaction
    - Private Smart Contract
- BSOS 做了什麼？

## Ethereum Transaction
### Transaction Model of [go-ethereum](https://github.com/ethereum/go-ethereum)
https://github.com/ethereum/go-ethereum/blob/master/core/types/transaction.go#L38-L61
```go
type Transaction struct {
	data txdata
	// caches
	hash atomic.Value
	size atomic.Value
	from atomic.Value
}

type txdata struct {
	AccountNonce uint64          `json:"nonce"    gencodec:"required"`
	Price        *big.Int        `json:"gasPrice" gencodec:"required"`
	GasLimit     uint64          `json:"gas"      gencodec:"required"`
	Recipient    *common.Address `json:"to"       rlp:"nil"` // nil means contract creation
	Amount       *big.Int        `json:"value"    gencodec:"required"`
	Payload      []byte          `json:"input"    gencodec:"required"`

	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`

	// This is only used when marshaling to JSON.
	Hash *common.Hash `json:"hash" rlp:"-"`
}
```
- 一筆 Ethereum 交易簡單用白話文說明大概是：
    ```
    某人 A (from) 給予另一人 B (Recipient) 一筆錢 (Amount)，並附帶一筆訊息 (Payload)
    ```
- 那其他參數呢？
    - 為了證明此交易由 A 發起，交易上區塊鏈前需被 A 的 [ECDSA](https://en.wikipedia.org/wiki/Elliptic_Curve_Digital_Signature_Algorithm) 私鑰簽名，簽名後的交易會帶入 V, R, S 值，稱為 raw transaction。
    - Ethereum 可透過 AccountNonce 防止[雙花](https://www.investopedia.com/terms/d/doublespending.asp)
        - 某 account 在區塊鏈執行過幾筆交易
    - Ethereum 發起一筆交易需支付手續費，與 Price 和 GasLimit 有關。
    - 交易成功上鏈後取得 Hash，可查詢交易明細，如透過 [Etherscan](https://etherscan.io/)。

### Make an Ethereum Transaction
- 由前段可知，在 Ethereum 上執行一筆交易有以下步驟
    1. 透過 transaction model 定義一筆 transaction
    2. 將此 transaction 簽名，產生 raw transaction
    3. raw transaction 發送至區塊鏈節點執行
    4. 取得 transaction hash，查詢交易明細
- ==Ethereum 交易可分成三種==
    - ETH 轉帳
    - 資訊上鏈
    - 智能合約相關
- 本文介紹兩種方式操作 Ethereum transaction
    - 透過 [Metamask](https://metamask.io/)
    - Coding (follow [Go Ethereum Book](https://goethereumbook.org/en/transfer-eth/))

#### [Metamask](https://metamask.io/)
- 保管使用者私鑰，輔助執行交易
    ![](https://i.imgur.com/BV9q7Jk.png)
- 若要ETH 轉帳，點選發送，填入交易對象 account address 後執行交易
![](https://i.imgur.com/Te3pBoY.png)
- 若要做到資訊上鏈，需額外設定
    - 設定 -> 進階 -> 顯示16進位資料
    - 發送時可填入要上鏈的資訊，需先[編碼](https://www.online-toolz.com/tools/text-hex-convertor.php)成 16 進位字串
    ![](https://i.imgur.com/DGQMumT.png)
    ![](https://i.imgur.com/iVzXE5P.png)
    - 交易成功後，可查詢[上鏈資訊](https://etherscan.io/tx/0xebf958145ccc88c8f488f9fa6208bd99be423356d99d819b9e8feee8c7ae26b6)，以下範例為 BSOS 發表文章存證於 Ethereum。
    ![](https://i.imgur.com/vvxw85Z.png)
- ==若要操作智能合約，需將合約編譯成 16 進位字串 bytecode，寫入 Payload 發送交易==，下段詳細說明。

#### Follow [Go Ethereum Book](https://goethereumbook.org/en/transfer-eth/) 發送交易
- 以下範例實作 Eth 轉帳
    - 需申請 [Infra](https://infura.io/) 帳號，取得 API key。
    - 後續段落會在 EE 聯盟鏈環境實際執行 go-ethereum 程式，本段略。
```go
package main

import (
    "context"
    "crypto/ecdsa"
    "fmt"
    "log"
    "math/big"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/core/types"
    "github.com/ethereum/go-ethereum/crypto"
    "github.com/ethereum/go-ethereum/ethclient"
)
func main() {
    // 連線區塊鏈，需帶入 infra API key。
    client, err := ethclient.Dial("https://rinkeby.infura.io")
    if err != nil {
        log.Fatal(err)
    }
    // 匯入私鑰
    privateKey, err := crypto.HexToECDSA("fad9c8855b740a0b7ed4c221dbad0f33a83a49cad6b3fe8d5817ac83d38b6a19")
    if err != nil {
        log.Fatal(err)
    }
    publicKey := privateKey.Public()
    publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
    if !ok {
        log.Fatal("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
    }
    // 以下取得 transaction model 所需的參數
    fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
    nonce, err := client.PendingNonceAt(context.Background(), fromAddress)
    if err != nil {
        log.Fatal(err)
    }
    value := big.NewInt(1000000000000000000) // in wei (1 eth)
    gasLimit := uint64(21000)                // in units
    gasPrice, err := client.SuggestGasPrice(context.Background())
    if err != nil {
        log.Fatal(err)
    }
    toAddress := common.HexToAddress("0x4592d8f8d7b001e72cb26a73e4fa1806a51ac79d")
    var data []byte
    // 製作交易
    tx := types.NewTransaction(nonce, toAddress, value, gasLimit, gasPrice, data)
    chainID, err := client.NetworkID(context.Background())
    if err != nil {
        log.Fatal(err)
    }
    // 簽名交易，產生 raw transaction
    signedTx, err := types.SignTx(tx, types.NewEIP155Signer(chainID), privateKey)
    if err != nil {
        log.Fatal(err)
    }
    // 發送交易至區塊鏈
    err = client.SendTransaction(context.Background(), signedTx)
    if err != nil {
        log.Fatal(err)
    }
    // 印出 transaction hash
    fmt.Printf("tx sent: %s", signedTx.Hash().Hex())
}
```
- 透過相同邏輯改變參數，在 types.NewTransaction 時寫入有效的 data 值，便可做到資訊上鏈與操作智能合約。

### Ethereum Smart Contract
- 關於智能合約的介紹，網路上已有相當多的資料，本文假設讀者對 Ethereum 智能合約已有基本概念，不加以贅述。以下節錄一段維基百科的內容：
    > 智能合約（英語：Smart contract；智能合同）是一種特殊協議，在區塊鏈內製定合約時使用，當中內含了程式碼函式 (Function)，亦能與其他合約進行互動、做決策、儲存資料及傳送以太幣等功能。
- 前段提到 Ethereum 智能合約包含 deploy、write 與 read 三類功能，其中 deploy 與 write 透過 transaction 實現。
- Ethereum 智能合約支援多種程式語言開發，本文採用 [Solidity](https://solidity.readthedocs.io/)，並透過 [Remix IDE](https://remix.ethereum.org/) 展示 Ballot.sol 合約範例的操作。該合約的內容與投票相關，以下直接複製 Remix 中程式碼：
```solidity
pragma solidity >=0.4.22 <0.7.0;
/** 
 * @title Ballot
 * @dev Implements voting process along with vote delegation
 */
contract Ballot {
   
    struct Voter {
        uint weight; // weight is accumulated by delegation
        bool voted;  // if true, that person already voted
        address delegate; // person delegated to
        uint vote;   // index of the voted proposal
    }
struct Proposal {
        // If you can limit the length to a certain number of bytes, 
        // always use one of bytes1 to bytes32 because they are much cheaper
        bytes32 name;   // short name (up to 32 bytes)
        uint voteCount; // number of accumulated votes
    }
address public chairperson;
mapping(address => Voter) public voters;
Proposal[] public proposals;
/** 
     * @dev Create a new ballot to choose one of 'proposalNames'.
     * @param proposalNames names of proposals
     */
    constructor(bytes32[] memory proposalNames) public {
        chairperson = msg.sender;
        voters[chairperson].weight = 1;
for (uint i = 0; i < proposalNames.length; i++) {
            // 'Proposal({...})' creates a temporary
            // Proposal object and 'proposals.push(...)'
            // appends it to the end of 'proposals'.
            proposals.push(Proposal({
                name: proposalNames[i],
                voteCount: 0
            }));
        }
    }
    
    /** 
     * @dev Give 'voter' the right to vote on this ballot. May only be called by 'chairperson'.
     * @param voter address of voter
     */
    function giveRightToVote(address voter) public {
        require(
            msg.sender == chairperson,
            "Only chairperson can give right to vote."
        );
        require(
            !voters[voter].voted,
            "The voter already voted."
        );
        require(voters[voter].weight == 0);
        voters[voter].weight = 1;
    }
/**
     * @dev Delegate your vote to the voter 'to'.
     * @param to address to which vote is delegated
     */
    function delegate(address to) public {
        Voter storage sender = voters[msg.sender];
        require(!sender.voted, "You already voted.");
        require(to != msg.sender, "Self-delegation is disallowed.");
while (voters[to].delegate != address(0)) {
            to = voters[to].delegate;
// We found a loop in the delegation, not allowed.
            require(to != msg.sender, "Found loop in delegation.");
        }
        sender.voted = true;
        sender.delegate = to;
        Voter storage delegate_ = voters[to];
        if (delegate_.voted) {
            // If the delegate already voted,
            // directly add to the number of votes
            proposals[delegate_.vote].voteCount += sender.weight;
        } else {
            // If the delegate did not vote yet,
            // add to her weight.
            delegate_.weight += sender.weight;
        }
    }
/**
     * @dev Give your vote (including votes delegated to you) to proposal 'proposals[proposal].name'.
     * @param proposal index of proposal in the proposals array
     */
    function vote(uint proposal) public {
        Voter storage sender = voters[msg.sender];
        require(sender.weight != 0, "Has no right to vote");
        require(!sender.voted, "Already voted.");
        sender.voted = true;
        sender.vote = proposal;
// If 'proposal' is out of the range of the array,
        // this will throw automatically and revert all
        // changes.
        proposals[proposal].voteCount += sender.weight;
    }
/** 
     * @dev Computes the winning proposal taking all previous votes into account.
     * @return winningProposal_ index of winning proposal in the proposals array
     */
    function winningProposal() public view
            returns (uint winningProposal_)
    {
        uint winningVoteCount = 0;
        for (uint p = 0; p < proposals.length; p++) {
            if (proposals[p].voteCount > winningVoteCount) {
                winningVoteCount = proposals[p].voteCount;
                winningProposal_ = p;
            }
        }
    }
/** 
     * @dev Calls winningProposal() function to get the index of the winner contained in the proposals array and then
     * @return winnerName_ the name of the winner
     */
    function winnerName() public view
            returns (bytes32 winnerName_)
    {
        winnerName_ = proposals[winningProposal()].name;
    }
}
```
- 我們可以將 Ballot 智能合約所有 function 分成三大類
    - 發佈智能合約 (deploy)
        - constructor：合約初始化建構，匯入候選人名單。
    - 將資料寫入智能合約 (write)
        - giveRightToVote：投票發起人賦予某 account 投票權
        - delegate：將投票權利轉移給其他 account
        - vote：投票
    - 讀取智能合約的資料 (read)
        - winningProposal：查看勝選者編號
        - winnerName：查看勝選者姓名
#### 透過 Remix + Metamask 操作合約
- Remix 需將 Deploy & run transactions 設為 Active
![](https://i.imgur.com/SgJx3XF.png)
- 編譯智能合約
    - 編譯後產生 ABI 與 Bytecode，是後續操作合約的重要資訊
![](https://i.imgur.com/nCM2wWz.png)
- 設定區塊鏈連線，選擇 Injected Web3
    - Remix 會與 Metamask 綁定
![](https://i.imgur.com/VpopHt2.png)
- 填寫 deploy 建構參數，ballot 範例需填寫候選人名單，是 bytes32 陣列。
    - 我們將 [Alice, Bob, Kevin] 型態轉換成 ["0x616c696365000000000000000000000000000000000000000000000000000000", "0x626f620000000000000000000000000000000000000000000000000000000000", "0x6b6576696e000000000000000000000000000000000000000000000000000000"]
    - 按下 Deploy，會跳出 Metamask 提示
    ![](https://i.imgur.com/TAngJLa.png)
    - 可從 Metamask 前往 Etherscan 查詢[交易明細](https://ropsten.etherscan.io/tx/0x2ab58ac6ff679abbe624c4f37389b302cab9395fd9bd0bb1cee0cd508467fc82)
    ![](https://i.imgur.com/MMLpC75.png)
    - 從交易明細找到這次部署智能合約的地址是：0x1f61e00ba21f01fcac5994103063b17d7c396629
- 在 Remix 中填入 contract address 可與合約互動
    ![](https://i.imgur.com/ahdZyfa.png)
    - 執行 vote function
        - 因為是 write，會觸發 Metamask
    ![](https://i.imgur.com/3sAfFxN.png)
    - 執行 winnerName function (read)
    ![](https://i.imgur.com/QUe30vp.png)
    - 解碼
    ![](https://i.imgur.com/wYZELN5.png)

#### 透過 go-ethereum 操作智能合約
- Follow Go Ethereum Book
    - [Deploy](https://goethereumbook.org/en/smart-contract-deploy/)
    - [Write](https://goethereumbook.org/en/smart-contract-write/)
    - [Read](https://goethereumbook.org/en/smart-contract-read/)
:::info
Go Ethereum Book 中與公鏈連線需取得 Infra API Key，我們在 EE 章節詳細說明。
:::

## Enterprise Ethereum Demo
- 前段說明 Ethereum 的 transaction，並實際操作智能合約 function。
- 本段進一步說明企業以太坊 (EE) 並實際操作 private transaction
    - Metamask 無法執行 private transaction，在本段完全捨棄。
    - 接下來將大量使用 Go 實作，不再透過 Remix 與合約互動。
- 可參考[企業以太坊解決了什麼問題](https://medium.com/bsos-taiwan/what-problems-has-entriprise-ethereum-solved-b4fde233342f)

### Private Transaction Indruduction
- 企業以太坊與 Ethereum 大致相同，多了 privacy 與 permission，本文著重 privacy 中最重要的 private transaction 說明。
- Private transaction 不需手續費，Price 設為 0。
- EE 節點掛載一個 private transaction manager 來加密與存取私交易的內容。
    - Quorum 推薦 [Tessera](https://github.com/jpmorganchase/tessera)
    - Besu 推薦 [Orion](https://github.com/PegaSysEng/orion)
    - BSOS 實作 [Crux](https://github.com/blk-io/crux)
- [EEA 如何規範 private transaction](https://entethalliance.github.io/client-spec/spec.html#sec-private-transactions)
    ```
    The privateFrom and privateFor parameters in the eea_sendTransactionAsync and eea_sendTransaction calls specify the public keys of the sender and the intended recipients, respectively, of a private transaction. The private transaction type is specified using the restriction parameter. The two defined private transaction types are:
    1. Restricted private transactions, where payload data is transmitted to and readable only by the parties to the transaction.
    2. Unrestricted private transactions, where encrypted payload data is transmitted to all nodes in the Enterprise Ethereum blockchain, but readable only by the parties to the transaction.
    ```
    - 一個 private transaction 包含三個與 privacy 相關的參數：
        - privateFrom，自己 private transaction manager 的公鑰
        - privateFor，其他私交易參與者的 private transaction manager 的公鑰陣列
        - restriction，限制私交易內容加密後是否同步到非參與者的節點
- ==一筆私交易除了 transaction model 中的參數，還會指定這筆交易的 "參與方節點"。==

### Private Smart Contract
- 透過私交易發佈的智能合約稱為私密智能合約 (private smart contract)
- 根據私交易的特性，交易內容只有參與方節點可以看見交易內容與隱私資訊。
- 使用流程
    - Deploy
        - 產生 deploy contract payload
        - 製作 transaction model，填入 payload，receiptent 為空
        - 簽名交易產生 raw transaction，上鏈執行。
        - 取得 contract address
    - Write
        - 產生 write contract payload
        - 製作 transaction model，填入 payload，receiptent 填入 contract address。
        - 簽名交易產生 raw transaction，上鏈執行。
    - Read
        - 透過 API

### Demo Envirement
- 準備 8GB RAM 以上 Ubuntu 環境
    - 本文使用 EC2 t2-large，Ubuntu 18.04。
- 安裝 git
- [安裝 Docker](https://phoenixnap.com/kb/how-to-install-docker-on-ubuntu-18-04)
    ```shell
    $ sudo apt-get update
    $ sudo apt-get remove docker docker-engine docker.io
    $ sudo apt install docker.io
    $ sudo groupadd docker
    $ sudo usermod -aG docker $USER
    $ exit # 重新登入
    ```
- [安裝 docker-compose](https://phoenixnap.com/kb/install-docker-compose-ubuntu)
    ```shell
    $ sudo curl -L "https://github.com/docker/compose/releases/download/1.24.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
	$ sudo chmod +x /usr/local/bin/docker-compose
    ```
- 安裝 Go 與 [gvm](https://blog.longwin.com.tw/2016/11/golang-gvm-go-version-manager-install-2016/)，選擇 Go 版本
    ```shell
    $ sudo apt install golang-go
    $ sudo apt-get install curl git mercurial make binutils bison gcc build-essential
    $ bash < <(curl -s -S -L https://raw.githubusercontent.com/moovweb/gvm/master/binscripts/gvm-installer)
    $ source /home/ubuntu/.gvm/scripts/gvm
    $ gvm install go1.13.12 --binary
    $ gvm use go1.13.12
    ```

#### [安裝 geth](https://geth.ethereum.org/docs/install-and-build/installing-geth)
- geth 是 go-ethereum client 端工具，可連線架設好的 EE (Quorum and Besu)。
```shell
$ sudo add-apt-repository -y ppa:ethereum/ethereum
$ sudo apt-get update
$ sudo apt-get install ethereum
```

#### 安裝 Quorum
- 透過 [quorum-maker](https://github.com/synechron-finlabs/quorum-maker) 安裝
```shell
$ git clone https://github.com/bsostech/quorum-maker
$ cd quorum-maker
$ ./setup.sh
    > 輸入聯盟鏈名稱
    > 輸入節點數
```
![](https://i.imgur.com/u3kDR7B.png)
- 上圖顯示安裝 Quorum 版本為 2.2.1，當中 public key 代表各節點 private transaction manager 公鑰。
    - quorum-maker 採用 [Tessera](https://github.com/jpmorganchase/tessera) 作為 private transaction manager
- 當前會產生一個聯盟鏈名稱的目錄，進入之後修改 docker-compose file，將 node1 port 導出：
    - 22000: API port
    - 22044: blockchain explorer port
    ```shell
    $ sudo vi bsos/docker-compose.yml
    ```
    ![](https://i.imgur.com/jJRJIox.png)
- 啟動 Quorum
```shell
$ cd bsos
$ docker-compose up -d
```
- 使用 geth 測試連線
```shell
$ geth attach http://localhost:20100
```
![](https://i.imgur.com/CIy4UFA.png)
- 透過 geth 在 Quorum 發送一筆 ETH 交易
```
> personal.unlockAccount("0xa27044134293cb1340829f5ac4e3263f175fb0ff","",0)
> eth.sendTransaction({from: '0xa27044134293cb1340829f5ac4e3263f175fb0ff', to: '0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73', value: '1000000000000'})
"0xfa388ade7d8e75e82306ab556fa1e2f279ff640fc06bce6df7c028c854f91996"
> eth.getBalance('0xFE3B557E8Fb62b89F4916B721be55cEb828dBd73')

1000000000000
```
- blockchain explorer
    - http://ip:20104
    ![](https://i.imgur.com/fURt3n4.png)

#### 安裝 Besu
- [官網](https://besu.hyperledger.org/en/stable/Tutorials/Examples/Privacy-Example)提供 docker-compose 方式快速建立 Besu 環境
    - 執行 run-privacy.sh 以實現可執行 private transaction 的節點環境
    - 參數選定共識機制，包含 ibft2、clique 等
```shell
$ git clone https://github.com/PegaSysEng/besu-sample-networks.git
$ cd besu-sample-networks
$ ./run-privacy.sh -c ibft2
```
- 查看 Besu 服務
    - 20000: API port (由 node1 8545 導出)
    - 25000: blockchain explorer
```shell
./list.sh
```
![](https://i.imgur.com/MNi0PL2.png)
- 使用 geth 測試連線
```shell
$ geth attach http://localhost:20100
```
![](https://i.imgur.com/QvL7cbx.png)
- blockchain explorer
    - http://ip:25000
    ![](https://i.imgur.com/nl2FYka.png)

#### 取得 Demo 專案
```shell
$ git clone https://github.com/yenkuanlee/Enterprise-Ethereum
```

### Quorum Private Transaction
- Quorum 直接使用 Ethereum 的 [transaction model](https://github.com/ethereum/go-ethereum/blob/master/core/types/transaction.go#L38-L61)
- Quorum transaction 的 Payload 需要加密
    - [官方文件](https://docs.goquorum.com/en/latest/Getting%20Started/api/)提到，發送私交易時，Payload 需透過 private transaction manager 提供的 storeraw 加密
    - API 會實作在 Quorum 專案的 [internal/ethapi/api.go](https://github.com/jpmorganchase/quorum/blob/master/internal/ethapi/api.go#L1528)
    :::info
    不幸的是，Quorum 一直到 2.6 版才透過 setPrivateTransactionHash 實作 Payload 加密 API，因此 quorum-maker 安裝的 Quorum 無法直接使用 private transaction 功能。
    BSOS 以 Crux 作為 private transaction manager，並在 Quorum 2.4 中實作 GetEncryptedHash 來加密  private transaction Payload。
    以下實作皆採用 BSOS Quorum (https://github.com/bsostech/quorum)
    :::
- 透過使用者私鑰簽名交易，產生 raw transaction
    - Quorum private transaction 簽名演算法與 Ethereum 不同
    - Ethereum 採 EIP155
    ```go
    signer = types.NewEIP155Signer(networkID)
    ```
    - Quorum 使用 HomesteadSigner
    ```go
    signer = types.HomesteadSigner{}
    ```
- 將 raw transaction 發送至區塊鏈執行
    - 參數除了 raw transaction 外，還需帶入 privateFor 字串陣列
- 範例可參考 Demo 專案的 [quorum/deploy/main.go](https://github.com/yenkuanlee/Enterprise-Ethereum/blob/master/quorum/deploy/main.go)
    - 此範例透過 private transaction 發佈一個私密合約，Payload (data) 內容與合約相關，下一段再詳細解釋。
    - 執行後回傳 transaction hash，可透過 Quorum blockchain explorer 查詢，或透過 geth 查詢。
```go
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
	bytecode := "0x608060405234801561001057600080fd5b50604051610e81380380610e818339810180604052602081101561003357600080fd5b81019080805164010000000081111561004b57600080fd5b8281019050602081018481111561006157600080fd5b815185602082028301116401000000008211171561007e57600080fd5b5050929190505050336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060018060008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000018190555060008090505b81518110156101bb5760026040805190810160405280848481518110151561015857fe5b90602001906020020151815260200160008152509080600181540180825580915050906001820390600052602060002090600202016000909192909190915060008201518160000155602082015181600101555050508080600101915050610134565b5050610cb5806101cc6000396000f3fe608060405260043610610088576000357c0100000000000000000000000000000000000000000000000000000000900480630121b93f1461008d578063013cf08b146100c85780632e4176cf1461011e5780635c19a95c14610175578063609ff1bd146101c65780639e7b8d61146101f1578063a3ec138d14610242578063e2ba53f0146102ec575b600080fd5b34801561009957600080fd5b506100c6600480360360208110156100b057600080fd5b8101908080359060200190929190505050610317565b005b3480156100d457600080fd5b50610101600480360360208110156100eb57600080fd5b81019080803590602001909291905050506104ba565b604051808381526020018281526020019250505060405180910390f35b34801561012a57600080fd5b506101336104ed565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561018157600080fd5b506101c46004803603602081101561019857600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610512565b005b3480156101d257600080fd5b506101db610938565b6040518082815260200191505060405180910390f35b3480156101fd57600080fd5b506102406004803603602081101561021457600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506109b3565b005b34801561024e57600080fd5b506102916004803603602081101561026557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610bfd565b60405180858152602001841515151581526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200194505050505060405180910390f35b3480156102f857600080fd5b50610301610c5a565b6040518082815260200191505060405180910390f35b6000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020905060008160000154141515156103d7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260148152602001807f486173206e6f20726967687420746f20766f746500000000000000000000000081525060200191505060405180910390fd5b8060010160009054906101000a900460ff1615151561045e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600e8152602001807f416c726561647920766f7465642e00000000000000000000000000000000000081525060200191505060405180910390fd5b60018160010160006101000a81548160ff021916908315150217905550818160020181905550806000015460028381548110151561049857fe5b9060005260206000209060020201600101600082825401925050819055505050565b6002818154811015156104c957fe5b90600052602060002090600202016000915090508060000154908060010154905082565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002090508060010160009054906101000a900460ff161515156105dc576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260128152602001807f596f7520616c726561647920766f7465642e000000000000000000000000000081525060200191505060405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610680576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601e8152602001807f53656c662d64656c65676174696f6e20697320646973616c6c6f7765642e000081525060200191505060405180910390fd5b5b600073ffffffffffffffffffffffffffffffffffffffff16600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614151561082757600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1691503373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610822576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260198152602001807f466f756e64206c6f6f7020696e2064656c65676174696f6e2e0000000000000081525060200191505060405180910390fd5b610681565b60018160010160006101000a81548160ff021916908315150217905550818160010160016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002090508060010160009054906101000a900460ff161561091c578160000154600282600201548154811015156108f957fe5b906000526020600020906002020160010160008282540192505081905550610933565b816000015481600001600082825401925050819055505b505050565b6000806000905060008090505b6002805490508110156109ae578160028281548110151561096257fe5b90600052602060002090600202016001015411156109a15760028181548110151561098957fe5b90600052602060002090600202016001015491508092505b8080600101915050610945565b505090565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515610a9d576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260288152602001807f4f6e6c79206368616972706572736f6e2063616e20676976652072696768742081526020017f746f20766f74652e00000000000000000000000000000000000000000000000081525060400191505060405180910390fd5b600160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160009054906101000a900460ff16151515610b62576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260188152602001807f54686520766f74657220616c726561647920766f7465642e000000000000000081525060200191505060405180910390fd5b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000154141515610bb357600080fd5b60018060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000018190555050565b60016020528060005260406000206000915090508060000154908060010160009054906101000a900460ff16908060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060020154905084565b60006002610c66610938565b815481101515610c7257fe5b90600052602060002090600202016000015490509056fea165627a7a7230582072f4679318cf41d402411ff4e56aa9084b22a14afb40f44471d4bd73c400d95b002900000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003416c696365000000000000000000000000000000000000000000000000000000426f6200000000000000000000000000000000000000000000000000000000004b6576696e000000000000000000000000000000000000000000000000000000"
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

	quorumtx := types.NewContractCreation(nonce, nil, gasLimit, big.NewInt(0), encryptedData)

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
```
- 透過 geth 查詢 transaction hash 交易明細
![](https://i.imgur.com/lR0uRtF.png)
    - status 0x1 代表交易成功
    - contractAddress 非空，代表此交易是發佈合約
- 查詢 Quorum blockchain explorer
    - 若為私交易成員，交易狀態顯示 private，可看到交易內容
    ![](https://i.imgur.com/25JqQgE.png)
    - 若非私交易成員，交易狀態顯示 hash only，看不到交易內容
    ![](https://i.imgur.com/IOsQbc5.png)

### Besu Private Transaction
- Besu private transaction 相較 Quorum 較複雜，可參考 [如何操作 Hyperledger Besu 的 Private Raw Transaction](https://medium.com/bsos-taiwan/how-to-create-besu-private-raw-transaction-13a651637fc7)。
    - ==Besu 要簽名的交易內容包含 EEA 規範的 privateFrom、privateFor 與 restriction，因此 Besu 無法直接使用 Ethereum 的 transaction model。==
- Besu 提供 [API](https://besu.hyperledger.org/en/stable/Reference/API-Methods/)，可直接安裝至 Postman。
- Besu 提出 privacy group 的概念
    - Besu 將一群參與者節點的 private transaction manager 組成一個 privacy group。
    - 發起 private transaction 時
    ```
    privacy group = privateFrom + privateFor
    ```
    - ==private transaction 中的 nonce 要填入 fromAddress 在此 privacy group 中的 nonce，稱為 private nonce。==
    - privacy group 可作 CRUD (local)，同一群參與者節點間可存在多個 privacy group。
    - ==現有的 Besu API 中，private nonce 的算法是錯的==，應該要計算出參與成員的 root privacy group hash，才有辦法取得 privat nonce。
- BSOS 開發的 [Besu Go SDK](https://github.com/bsostech/go-besu) 可快速透過使用者私鑰簽名交易，產生 raw transaction，並發送至區塊鏈執行。
    - Besu private transaction 簽名演算法與 Ethereum 同為 EIP155
- 範例可參考 Demo 專案的 [besu/deploy/main.go](https://github.com/yenkuanlee/Enterprise-Ethereum/blob/master/quorum/deploy/main.go)
    ```go
    package main

    import (
        "context"
        "crypto/ecdsa"
        "log"
        "math/big"

        "github.com/ethereum/go-ethereum/common/hexutil"
        "github.com/ethereum/go-ethereum/common"
        "github.com/ethereum/go-ethereum/crypto"
        "github.com/ethereum/go-ethereum/ethclient"
        "github.com/ethereum/go-ethereum/rlp"
        "github.com/ethereum/go-ethereum/rpc"

        "github.com/bsostech/go-besu/privacy"
        "github.com/bsostech/go-besu/types"
    )

    func main() {
        privateFromString := "A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo="
        privateFor1String := "Ko2bVqD+nNlNYL5EE7y3IdOnviftjiizpjRt+HTuFBs="
        privateFor2String := "k2zXEin4Ip/qBGlRkJejnGWdP9cjkK+DAvKNW31L2C8="
        privateFrom, _ := privacy.ToPublicKey(privateFromString)
        privateFor1, _ := privacy.ToPublicKey(privateFor1String)
        privateFor2, _ := privacy.ToPublicKey(privateFor2String)
        privateFor := [][]byte{privateFor1, privateFor2}
        participants := []*privacy.PublicKey{&privateFrom, &privateFor1, &privateFor2}

        bytecode := "0x608060405234801561001057600080fd5b50604051610e81380380610e818339810180604052602081101561003357600080fd5b81019080805164010000000081111561004b57600080fd5b8281019050602081018481111561006157600080fd5b815185602082028301116401000000008211171561007e57600080fd5b5050929190505050336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060018060008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000018190555060008090505b81518110156101bb5760026040805190810160405280848481518110151561015857fe5b90602001906020020151815260200160008152509080600181540180825580915050906001820390600052602060002090600202016000909192909190915060008201518160000155602082015181600101555050508080600101915050610134565b5050610cb5806101cc6000396000f3fe608060405260043610610088576000357c0100000000000000000000000000000000000000000000000000000000900480630121b93f1461008d578063013cf08b146100c85780632e4176cf1461011e5780635c19a95c14610175578063609ff1bd146101c65780639e7b8d61146101f1578063a3ec138d14610242578063e2ba53f0146102ec575b600080fd5b34801561009957600080fd5b506100c6600480360360208110156100b057600080fd5b8101908080359060200190929190505050610317565b005b3480156100d457600080fd5b50610101600480360360208110156100eb57600080fd5b81019080803590602001909291905050506104ba565b604051808381526020018281526020019250505060405180910390f35b34801561012a57600080fd5b506101336104ed565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561018157600080fd5b506101c46004803603602081101561019857600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610512565b005b3480156101d257600080fd5b506101db610938565b6040518082815260200191505060405180910390f35b3480156101fd57600080fd5b506102406004803603602081101561021457600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506109b3565b005b34801561024e57600080fd5b506102916004803603602081101561026557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610bfd565b60405180858152602001841515151581526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200194505050505060405180910390f35b3480156102f857600080fd5b50610301610c5a565b6040518082815260200191505060405180910390f35b6000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020905060008160000154141515156103d7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260148152602001807f486173206e6f20726967687420746f20766f746500000000000000000000000081525060200191505060405180910390fd5b8060010160009054906101000a900460ff1615151561045e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600e8152602001807f416c726561647920766f7465642e00000000000000000000000000000000000081525060200191505060405180910390fd5b60018160010160006101000a81548160ff021916908315150217905550818160020181905550806000015460028381548110151561049857fe5b9060005260206000209060020201600101600082825401925050819055505050565b6002818154811015156104c957fe5b90600052602060002090600202016000915090508060000154908060010154905082565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002090508060010160009054906101000a900460ff161515156105dc576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260128152602001807f596f7520616c726561647920766f7465642e000000000000000000000000000081525060200191505060405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610680576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601e8152602001807f53656c662d64656c65676174696f6e20697320646973616c6c6f7765642e000081525060200191505060405180910390fd5b5b600073ffffffffffffffffffffffffffffffffffffffff16600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614151561082757600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1691503373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610822576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260198152602001807f466f756e64206c6f6f7020696e2064656c65676174696f6e2e0000000000000081525060200191505060405180910390fd5b610681565b60018160010160006101000a81548160ff021916908315150217905550818160010160016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002090508060010160009054906101000a900460ff161561091c578160000154600282600201548154811015156108f957fe5b906000526020600020906002020160010160008282540192505081905550610933565b816000015481600001600082825401925050819055505b505050565b6000806000905060008090505b6002805490508110156109ae578160028281548110151561096257fe5b90600052602060002090600202016001015411156109a15760028181548110151561098957fe5b90600052602060002090600202016001015491508092505b8080600101915050610945565b505090565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515610a9d576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260288152602001807f4f6e6c79206368616972706572736f6e2063616e20676976652072696768742081526020017f746f20766f74652e00000000000000000000000000000000000000000000000081525060400191505060405180910390fd5b600160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160009054906101000a900460ff16151515610b62576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260188152602001807f54686520766f74657220616c726561647920766f7465642e000000000000000081525060200191505060405180910390fd5b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000154141515610bb357600080fd5b60018060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000018190555050565b60016020528060005260406000206000915090508060000154908060010160009054906101000a900460ff16908060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060020154905084565b60006002610c66610938565b815481101515610c7257fe5b90600052602060002090600202016000015490509056fea165627a7a7230582072f4679318cf41d402411ff4e56aa9084b22a14afb40f44471d4bd73c400d95b002900000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003416c696365000000000000000000000000000000000000000000000000000000426f6200000000000000000000000000000000000000000000000000000000004b6576696e000000000000000000000000000000000000000000000000000000"
        data, _ := hexutil.Decode(bytecode)
        rpcClient, _ := rpc.Dial("http://localhost:20000")
        ethClient := ethclient.NewClient(rpcClient)
        privateKey, _ := crypto.HexToECDSA("8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63")
        publicKey := privateKey.Public()
        publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
        fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
        gasLimit := uint64(3000000)
        networkID, _ := ethClient.NetworkID(context.TODO())

        // get private nonce
        // 1. find private group
        priv := privacy.NewPrivacy(rpcClient)
        rootPrivacyGroup := priv.FindRootPrivacyGroup(participants)
        // 2. get private nonce
        privateNonce, _ := priv.PrivateNonce(fromAddress, rootPrivacyGroup)

        besutx := types.NewContractCreation(privateNonce, nil, gasLimit, big.NewInt(0), data, privateFrom, privateFor)
        besuSignedTx, _ := besutx.SignTx(networkID, privateKey)
        besuRawTxData, _ := rlp.EncodeToBytes(besuSignedTx)
        besuRawTxData = append(besuRawTxData[:1], besuRawTxData[4:]...) // KEVIN hack, remove redundant dust
        var txHash common.Hash
        rpcClient.CallContext(context.TODO(), &txHash, "eea_sendRawTransaction", hexutil.Encode(besuRawTxData))
        log.Println(txHash.Hex())
    }
    ```
    - 此範例透過 private transaction 發佈一個私密合約，Payload (data) 內容與合約相關，下一段再詳細解釋。
    - 執行後回傳 transaction hash，可透過 Besu blockchain explorer 查詢，或透過 geth 查詢。
    - ==Besu 有兩種 transaction receipt==，可分別透過 API 取得：
        - eth_getTransactionReceipt
        ```json
        {
          "jsonrpc": "2.0",
          "id": 1,
          "result": {
            "blockHash": "0xb2162d35ec82ed67d021151516dbe08cc9df0c84f0ade00bcc2c7c0f7e477c3c",
            "blockNumber": "0x92797",
            "contractAddress": null,
            "cumulativeGasUsed": "0x5a88",
            "from": "0x791a7e7d6189b19bfa7aa0a1f0282d0a2f4d0425",
            "gasUsed": "0x5a88",
            "logs": [],
            "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "status": "0x1",
            "to": "0x000000000000000000000000000000000000007e",
            "transactionHash": "0xd5e909feba63514b4775108adfbe1713a03f478f3d1dd114b08c3e9d0c593399",
            "transactionIndex": "0x0"
          }
        }
        ```
        - priv_getTransactionReceipt
        ```json
        {
          "jsonrpc": "2.0",
          "id": 1,
          "result": {
            "contractAddress": "0xf55bab0302fade797dd18dd425a2a1b7d6ee66f6",
            "from": "0xfe3b557e8fb62b89f4916b721be55ceb828dbd73",
            "output": "0x608060405260043610610088576000357c0100000000000000000000000000000000000000000000000000000000900480630121b93f1461008d578063013cf08b146100c85780632e4176cf1461011e5780635c19a95c14610175578063609ff1bd146101c65780639e7b8d61146101f1578063a3ec138d14610242578063e2ba53f0146102ec575b600080fd5b34801561009957600080fd5b506100c6600480360360208110156100b057600080fd5b8101908080359060200190929190505050610317565b005b3480156100d457600080fd5b50610101600480360360208110156100eb57600080fd5b81019080803590602001909291905050506104ba565b604051808381526020018281526020019250505060405180910390f35b34801561012a57600080fd5b506101336104ed565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561018157600080fd5b506101c46004803603602081101561019857600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610512565b005b3480156101d257600080fd5b506101db610938565b6040518082815260200191505060405180910390f35b3480156101fd57600080fd5b506102406004803603602081101561021457600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506109b3565b005b34801561024e57600080fd5b506102916004803603602081101561026557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610bfd565b60405180858152602001841515151581526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200194505050505060405180910390f35b3480156102f857600080fd5b50610301610c5a565b6040518082815260200191505060405180910390f35b6000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020905060008160000154141515156103d7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260148152602001807f486173206e6f20726967687420746f20766f746500000000000000000000000081525060200191505060405180910390fd5b8060010160009054906101000a900460ff1615151561045e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600e8152602001807f416c726561647920766f7465642e00000000000000000000000000000000000081525060200191505060405180910390fd5b60018160010160006101000a81548160ff021916908315150217905550818160020181905550806000015460028381548110151561049857fe5b9060005260206000209060020201600101600082825401925050819055505050565b6002818154811015156104c957fe5b90600052602060002090600202016000915090508060000154908060010154905082565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002090508060010160009054906101000a900460ff161515156105dc576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260128152602001807f596f7520616c726561647920766f7465642e000000000000000000000000000081525060200191505060405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610680576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601e8152602001807f53656c662d64656c65676174696f6e20697320646973616c6c6f7765642e000081525060200191505060405180910390fd5b5b600073ffffffffffffffffffffffffffffffffffffffff16600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614151561082757600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1691503373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610822576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260198152602001807f466f756e64206c6f6f7020696e2064656c65676174696f6e2e0000000000000081525060200191505060405180910390fd5b610681565b60018160010160006101000a81548160ff021916908315150217905550818160010160016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002090508060010160009054906101000a900460ff161561091c578160000154600282600201548154811015156108f957fe5b906000526020600020906002020160010160008282540192505081905550610933565b816000015481600001600082825401925050819055505b505050565b6000806000905060008090505b6002805490508110156109ae578160028281548110151561096257fe5b90600052602060002090600202016001015411156109a15760028181548110151561098957fe5b90600052602060002090600202016001015491508092505b8080600101915050610945565b505090565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515610a9d576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260288152602001807f4f6e6c79206368616972706572736f6e2063616e20676976652072696768742081526020017f746f20766f74652e00000000000000000000000000000000000000000000000081525060400191505060405180910390fd5b600160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160009054906101000a900460ff16151515610b62576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260188152602001807f54686520766f74657220616c726561647920766f7465642e000000000000000081525060200191505060405180910390fd5b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000154141515610bb357600080fd5b60018060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000018190555050565b60016020528060005260406000206000915090508060000154908060010160009054906101000a900460ff16908060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060020154905084565b60006002610c66610938565b815481101515610c7257fe5b90600052602060002090600202016000015490509056fea165627a7a7230582072f4679318cf41d402411ff4e56aa9084b22a14afb40f44471d4bd73c400d95b0029",
            "commitmentHash": "0xd5e909feba63514b4775108adfbe1713a03f478f3d1dd114b08c3e9d0c593399",
            "transactionHash": "0xf922d71df1a671aa575b6a66302c5a7ff5099e1cd1490fdccfed175a8df88eb5",
            "privateFrom": "A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo=",
            "privateFor": [
              "Ko2bVqD+nNlNYL5EE7y3IdOnviftjiizpjRt+HTuFBs=",
              "k2zXEin4Ip/qBGlRkJejnGWdP9cjkK+DAvKNW31L2C8="
            ],
            "status": "0x1",
            "logs": [],
            "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
            "blockHash": "0xb2162d35ec82ed67d021151516dbe08cc9df0c84f0ade00bcc2c7c0f7e477c3c",
            "blockNumber": "0x92797",
            "transactionIndex": "0x0"
          }
        }
        ```

### Quorum vs Besu
- Quorum 直接使用 Ethereum transaction model，Besu 則否。
    - Quorum 的 privacy 相關參數是沒有被簽名的，可能被竄改。
- Quorum 使用 Ethereum 相同的 nonce，Besu 使用 private nonce。
    - Besu 執行私交易後，private nonce 改變，public nonce 則沒變。
    - 外人可從 nonce 推敲出某 account 在 Quorum 執行了私交易，在 Besu 則無法。
- Quorum transaction receipt 與 Ethereum 相同，Besu 則多了 private transaction receipt。
    - Quorum transaction receipt 每個人都可以查詢，但只有參與者可解讀 input data。
    - 雖然 Quorum 非參與者讀不懂 input data，依然知道此交易行為 (如發佈合約)，並知道交易發起者帳號，與發佈的智能合約位置等資訊。
    - Besu 則將隱私的資訊放在 private transaction receipt。
- 誰是參與者？
    - Quorum 無法查詢一個 transaction 的參與者
        - 應用上可能存在欺騙，例如 A 拿某個 contract address 跟 B 說這合約參與者只有 AB 雙方，但其實 A 在發佈合約時偷偷指定 C 也為參與者，B 卻無從確認。
    - Besu 則可透過 private transaction receipt 取得 privateFrom 與 privateFor 資訊。
- 比較下來，Quorum 較接近原生的 Ethereum，Besu 則對 privacy 下更多功夫。

### Transaction Payload of Smart Contract
- 不論 Ethereum、Quorum 或 Besu，智能合約的 deploy 與 write 皆透過 transaction payload 來定義交易行為。
- Deploy contract 相關的 payload 可拆解成兩部分：
    - 第一部分是智能合約編譯後的機器代碼
    - 第二部分是 constructor function 的參數打包
- 產生 Deploy smart contract payload 的[範例](https://github.com/yenkuanlee/Enterprise-Ethereum/blob/master/data/constructor/main.go)：
```go
package main

import (
	"log"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
)

const contractAbi = "[{\"constant\":false,\"inputs\":[{\"name\":\"proposal\",\"type\":\"uint256\"}],\"name\":\"vote\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"proposals\",\"outputs\":[{\"name\":\"name\",\"type\":\"bytes32\"},{\"name\":\"voteCount\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"chairperson\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"to\",\"type\":\"address\"}],\"name\":\"delegate\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"winningProposal\",\"outputs\":[{\"name\":\"winningProposal_\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"voter\",\"type\":\"address\"}],\"name\":\"giveRightToVote\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"voters\",\"outputs\":[{\"name\":\"weight\",\"type\":\"uint256\"},{\"name\":\"voted\",\"type\":\"bool\"},{\"name\":\"delegate\",\"type\":\"address\"},{\"name\":\"vote\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"winnerName\",\"outputs\":[{\"name\":\"winnerName_\",\"type\":\"bytes32\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"proposalNames\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"
const byteCode = "0x608060405234801561001057600080fd5b50604051610e81380380610e818339810180604052602081101561003357600080fd5b81019080805164010000000081111561004b57600080fd5b8281019050602081018481111561006157600080fd5b815185602082028301116401000000008211171561007e57600080fd5b5050929190505050336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060018060008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000018190555060008090505b81518110156101bb5760026040805190810160405280848481518110151561015857fe5b90602001906020020151815260200160008152509080600181540180825580915050906001820390600052602060002090600202016000909192909190915060008201518160000155602082015181600101555050508080600101915050610134565b5050610cb5806101cc6000396000f3fe608060405260043610610088576000357c0100000000000000000000000000000000000000000000000000000000900480630121b93f1461008d578063013cf08b146100c85780632e4176cf1461011e5780635c19a95c14610175578063609ff1bd146101c65780639e7b8d61146101f1578063a3ec138d14610242578063e2ba53f0146102ec575b600080fd5b34801561009957600080fd5b506100c6600480360360208110156100b057600080fd5b8101908080359060200190929190505050610317565b005b3480156100d457600080fd5b50610101600480360360208110156100eb57600080fd5b81019080803590602001909291905050506104ba565b604051808381526020018281526020019250505060405180910390f35b34801561012a57600080fd5b506101336104ed565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561018157600080fd5b506101c46004803603602081101561019857600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610512565b005b3480156101d257600080fd5b506101db610938565b6040518082815260200191505060405180910390f35b3480156101fd57600080fd5b506102406004803603602081101561021457600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506109b3565b005b34801561024e57600080fd5b506102916004803603602081101561026557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610bfd565b60405180858152602001841515151581526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200194505050505060405180910390f35b3480156102f857600080fd5b50610301610c5a565b6040518082815260200191505060405180910390f35b6000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020905060008160000154141515156103d7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260148152602001807f486173206e6f20726967687420746f20766f746500000000000000000000000081525060200191505060405180910390fd5b8060010160009054906101000a900460ff1615151561045e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600e8152602001807f416c726561647920766f7465642e00000000000000000000000000000000000081525060200191505060405180910390fd5b60018160010160006101000a81548160ff021916908315150217905550818160020181905550806000015460028381548110151561049857fe5b9060005260206000209060020201600101600082825401925050819055505050565b6002818154811015156104c957fe5b90600052602060002090600202016000915090508060000154908060010154905082565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002090508060010160009054906101000a900460ff161515156105dc576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260128152602001807f596f7520616c726561647920766f7465642e000000000000000000000000000081525060200191505060405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610680576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601e8152602001807f53656c662d64656c65676174696f6e20697320646973616c6c6f7765642e000081525060200191505060405180910390fd5b5b600073ffffffffffffffffffffffffffffffffffffffff16600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614151561082757600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1691503373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610822576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260198152602001807f466f756e64206c6f6f7020696e2064656c65676174696f6e2e0000000000000081525060200191505060405180910390fd5b610681565b60018160010160006101000a81548160ff021916908315150217905550818160010160016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002090508060010160009054906101000a900460ff161561091c578160000154600282600201548154811015156108f957fe5b906000526020600020906002020160010160008282540192505081905550610933565b816000015481600001600082825401925050819055505b505050565b6000806000905060008090505b6002805490508110156109ae578160028281548110151561096257fe5b90600052602060002090600202016001015411156109a15760028181548110151561098957fe5b90600052602060002090600202016001015491508092505b8080600101915050610945565b505090565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515610a9d576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260288152602001807f4f6e6c79206368616972706572736f6e2063616e20676976652072696768742081526020017f746f20766f74652e00000000000000000000000000000000000000000000000081525060400191505060405180910390fd5b600160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160009054906101000a900460ff16151515610b62576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260188152602001807f54686520766f74657220616c726561647920766f7465642e000000000000000081525060200191505060405180910390fd5b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000154141515610bb357600080fd5b60018060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000018190555050565b60016020528060005260406000206000915090508060000154908060010160009054906101000a900460ff16908060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060020154905084565b60006002610c66610938565b815481101515610c7257fe5b90600052602060002090600202016000015490509056fea165627a7a7230582072f4679318cf41d402411ff4e56aa9084b22a14afb40f44471d4bd73c400d95b0029"

func main() {
	// deploy contract
	proposalNames := []string{"Alice", "Bob", "Kevin"}
	names := make([][32]byte, 0, len(proposalNames))
	for i := range proposalNames {
		newArg := [32]byte{}
		copy(newArg[:], proposalNames[i])
		names = append(names, newArg)
	}
	parsedABI, _ := abi.JSON(strings.NewReader(contractAbi))
	arguments, _ := parsedABI.Pack("", names)
	data := append(common.FromHex(byteCode), arguments...)
	log.Println(hexutil.Encode(data))
}
```
- 此範例給定三位候選人，最後印出 ballot 的 deploy payload，當中 ABI 與 Bytecode 可透過 Remix 取得
![](https://i.imgur.com/G7OnHYQ.png)
- 而 write contract 相關的 payload 也可拆解成兩部分：
    - 第一部分是 function name
    - 第二部分是 constructor function 的參數打包
- 產生 write smart contract payload 的[範例]()：
```go
package main

import (
	"log"
	"math/big"
	"strings"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common/hexutil"
)
const contractAbi = "[{\"constant\":false,\"inputs\":[{\"name\":\"proposal\",\"type\":\"uint256\"}],\"name\":\"vote\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"proposals\",\"outputs\":[{\"name\":\"name\",\"type\":\"bytes32\"},{\"name\":\"voteCount\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"chairperson\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"to\",\"type\":\"address\"}],\"name\":\"delegate\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"winningProposal\",\"outputs\":[{\"name\":\"winningProposal_\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"voter\",\"type\":\"address\"}],\"name\":\"giveRightToVote\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"voters\",\"outputs\":[{\"name\":\"weight\",\"type\":\"uint256\"},{\"name\":\"voted\",\"type\":\"bool\"},{\"name\":\"delegate\",\"type\":\"address\"},{\"name\":\"vote\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"winnerName\",\"outputs\":[{\"name\":\"winnerName_\",\"type\":\"bytes32\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"proposalNames\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"
func main() {
	parsedABI, _ := abi.JSON(strings.NewReader(contractAbi))
	arguments, _ := parsedABI.Pack("vote", big.NewInt(2))
	log.Println(hexutil.Encode(arguments))
}
```
- 此範例 function 為 vote，參數 2 代表投給 2 號候選人。

### Quorum Private Smart Contract
- deploy 與 write 透過 private transaction 實現
- read 可透過 Quorum API eth_call 實現

#### Quorum Deploy Private Contract
- Deploy contract 時 transaction model 中的 Recipient 值為空，Payload 值由前一段說明方式產生。
- 事先產生 payload，再執行 deploy Quorum private smart contract [範例](https://github.com/yenkuanlee/Enterprise-Ethereum/blob/master/quorum/deploy/main.go)
    - 執行後回傳 transaction hash
    - 透過 eth_getTransactionReceipt 取得交易明細，記下 contract address 以利後續操作合約。
```go
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
    // 事先產生 payload
    bytecode := "0x608060405234801561001057600080fd5b50604051610e81380380610e818339810180604052602081101561003357600080fd5b81019080805164010000000081111561004b57600080fd5b8281019050602081018481111561006157600080fd5b815185602082028301116401000000008211171561007e57600080fd5b5050929190505050336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060018060008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000018190555060008090505b81518110156101bb5760026040805190810160405280848481518110151561015857fe5b90602001906020020151815260200160008152509080600181540180825580915050906001820390600052602060002090600202016000909192909190915060008201518160000155602082015181600101555050508080600101915050610134565b5050610cb5806101cc6000396000f3fe608060405260043610610088576000357c0100000000000000000000000000000000000000000000000000000000900480630121b93f1461008d578063013cf08b146100c85780632e4176cf1461011e5780635c19a95c14610175578063609ff1bd146101c65780639e7b8d61146101f1578063a3ec138d14610242578063e2ba53f0146102ec575b600080fd5b34801561009957600080fd5b506100c6600480360360208110156100b057600080fd5b8101908080359060200190929190505050610317565b005b3480156100d457600080fd5b50610101600480360360208110156100eb57600080fd5b81019080803590602001909291905050506104ba565b604051808381526020018281526020019250505060405180910390f35b34801561012a57600080fd5b506101336104ed565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561018157600080fd5b506101c46004803603602081101561019857600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610512565b005b3480156101d257600080fd5b506101db610938565b6040518082815260200191505060405180910390f35b3480156101fd57600080fd5b506102406004803603602081101561021457600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506109b3565b005b34801561024e57600080fd5b506102916004803603602081101561026557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610bfd565b60405180858152602001841515151581526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200194505050505060405180910390f35b3480156102f857600080fd5b50610301610c5a565b6040518082815260200191505060405180910390f35b6000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020905060008160000154141515156103d7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260148152602001807f486173206e6f20726967687420746f20766f746500000000000000000000000081525060200191505060405180910390fd5b8060010160009054906101000a900460ff1615151561045e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600e8152602001807f416c726561647920766f7465642e00000000000000000000000000000000000081525060200191505060405180910390fd5b60018160010160006101000a81548160ff021916908315150217905550818160020181905550806000015460028381548110151561049857fe5b9060005260206000209060020201600101600082825401925050819055505050565b6002818154811015156104c957fe5b90600052602060002090600202016000915090508060000154908060010154905082565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002090508060010160009054906101000a900460ff161515156105dc576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260128152602001807f596f7520616c726561647920766f7465642e000000000000000000000000000081525060200191505060405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610680576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601e8152602001807f53656c662d64656c65676174696f6e20697320646973616c6c6f7765642e000081525060200191505060405180910390fd5b5b600073ffffffffffffffffffffffffffffffffffffffff16600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614151561082757600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1691503373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610822576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260198152602001807f466f756e64206c6f6f7020696e2064656c65676174696f6e2e0000000000000081525060200191505060405180910390fd5b610681565b60018160010160006101000a81548160ff021916908315150217905550818160010160016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002090508060010160009054906101000a900460ff161561091c578160000154600282600201548154811015156108f957fe5b906000526020600020906002020160010160008282540192505081905550610933565b816000015481600001600082825401925050819055505b505050565b6000806000905060008090505b6002805490508110156109ae578160028281548110151561096257fe5b90600052602060002090600202016001015411156109a15760028181548110151561098957fe5b90600052602060002090600202016001015491508092505b8080600101915050610945565b505090565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515610a9d576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260288152602001807f4f6e6c79206368616972706572736f6e2063616e20676976652072696768742081526020017f746f20766f74652e00000000000000000000000000000000000000000000000081525060400191505060405180910390fd5b600160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160009054906101000a900460ff16151515610b62576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260188152602001807f54686520766f74657220616c726561647920766f7465642e000000000000000081525060200191505060405180910390fd5b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000154141515610bb357600080fd5b60018060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000018190555050565b60016020528060005260406000206000915090508060000154908060010160009054906101000a900460ff16908060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060020154905084565b60006002610c66610938565b815481101515610c7257fe5b90600052602060002090600202016000015490509056fea165627a7a7230582072f4679318cf41d402411ff4e56aa9084b22a14afb40f44471d4bd73c400d95b002900000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003416c696365000000000000000000000000000000000000000000000000000000426f6200000000000000000000000000000000000000000000000000000000004b6576696e000000000000000000000000000000000000000000000000000000"
    data, _ := hexutil.Decode(bytecode)
    // 區塊鏈連線
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

    // 透過 NewContractCreation 產生 transaction
    // receiptent 是 nil
    quorumtx := types.NewContractCreation(nonce, nil, gasLimit, big.NewInt(0), encryptedData)

    // 定義交易的簽名器
    signer := types.HomesteadSigner{}
    // 簽名交易
    signedTx, _ := types.SignTx(quorumtx, signer, privateKey)
    // 定義 privateFor
    args := &client.SendRawTxArgs{
        PrivateFor: []string{"mmQsRWMkSRWAzvIj6szVOADGlmStS1bSBBdKgpYXTS4="},
    }
    // 編碼
    privateRawTransaction, _ := rlp.EncodeToBytes(signedTx)
    // 至區塊鏈執行交易
    var txHash common.Hash
    rpcClient.CallContext(context.TODO(), &txHash, "eth_sendRawPrivateTransaction", hexutil.Encode(privateRawTransaction), args)
    log.Println(txHash.Hex())
}
```

#### Quorum Write Private Contract
- Write contract 時 transaction model Payload 值由前一段說明方式產生
- 事先產生 payload，再執行 write Quorum private smart contract [範例](https://github.com/yenkuanlee/Enterprise-Ethereum/blob/master/quorum/write/main.go)
    - 此範例執行 vote
    - transaction 中 receiptent 參數是 contract address
```go
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
```

#### Quorum Read Private Contract
- 查詢區塊鏈狀態，透過 eth_call 實作
    - eth_call 需帶入一個 message 參數，包含 contract address，以及 read function 的參數打包。
- 以下[範例](https://github.com/yenkuanlee/Enterprise-Ethereum/blob/master/quorum/read/main.go)查詢當前最高票候選人
```go
package main

import (
	"context"
	"log"
	"strings"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/rpc"
)

const contractAbi = "[{\"constant\":false,\"inputs\":[{\"name\":\"proposal\",\"type\":\"uint256\"}],\"name\":\"vote\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"uint256\"}],\"name\":\"proposals\",\"outputs\":[{\"name\":\"name\",\"type\":\"bytes32\"},{\"name\":\"voteCount\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"chairperson\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"to\",\"type\":\"address\"}],\"name\":\"delegate\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"winningProposal\",\"outputs\":[{\"name\":\"winningProposal_\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":false,\"inputs\":[{\"name\":\"voter\",\"type\":\"address\"}],\"name\":\"giveRightToVote\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"address\"}],\"name\":\"voters\",\"outputs\":[{\"name\":\"weight\",\"type\":\"uint256\"},{\"name\":\"voted\",\"type\":\"bool\"},{\"name\":\"delegate\",\"type\":\"address\"},{\"name\":\"vote\",\"type\":\"uint256\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"constant\":true,\"inputs\":[],\"name\":\"winnerName\",\"outputs\":[{\"name\":\"winnerName_\",\"type\":\"bytes32\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"name\":\"proposalNames\",\"type\":\"bytes32[]\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\"}]"

func main() {
	rpcClient, _ := rpc.Dial("http://localhost:20100")
	contractAddress := common.HexToAddress("0xfeae27388a65ee984f452f86effed42aabd438fd")
	parsedABI, _ := abi.JSON(strings.NewReader(contractAbi))
	winner, _ := parsedABI.Pack("winnerName")
	msg := map[string]interface{}{
		"to":   contractAddress,
		"data": hexutil.Bytes(winner),
	}
	var result interface{}
	rpcClient.CallContext(context.TODO(), &result, "eth_call", msg, "latest")
	output, _ := hexutil.Decode(result.(string))
	log.Println(string(output))
}
```
- 以上範例執行結果是 Kevin (2 號候選人)

### Besu Private Smart Contract
- deploy 與 write 透過 private transaction 實現
- read 可透過 Besu API priv_call 實現

#### Besu Deploy Private Contract
- Deploy contract 時 transaction model 中的 Recipient 值為空，Payload 值由前一段說明方式產生。
- 事先產生 payload，再執行 deploy Besu private smart contract [範例](https://github.com/yenkuanlee/Enterprise-Ethereum/blob/master/besu/deploy/main.go)
    ```go
    package main

    import (
        "context"
        "crypto/ecdsa"
        "log"
        "math/big"

        "github.com/ethereum/go-ethereum/common/hexutil"
        "github.com/ethereum/go-ethereum/common"
        "github.com/ethereum/go-ethereum/crypto"
        "github.com/ethereum/go-ethereum/ethclient"
        "github.com/ethereum/go-ethereum/rlp"
        "github.com/ethereum/go-ethereum/rpc"

        "github.com/bsostech/go-besu/privacy"
        "github.com/bsostech/go-besu/types"
    )

    func main() {
        privateFromString := "A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo="
        privateFor1String := "Ko2bVqD+nNlNYL5EE7y3IdOnviftjiizpjRt+HTuFBs="
        privateFor2String := "k2zXEin4Ip/qBGlRkJejnGWdP9cjkK+DAvKNW31L2C8="
        privateFrom, _ := privacy.ToPublicKey(privateFromString)
        privateFor1, _ := privacy.ToPublicKey(privateFor1String)
        privateFor2, _ := privacy.ToPublicKey(privateFor2String)
        privateFor := [][]byte{privateFor1, privateFor2}
        participants := []*privacy.PublicKey{&privateFrom, &privateFor1, &privateFor2}

        bytecode := "0x608060405234801561001057600080fd5b50604051610e81380380610e818339810180604052602081101561003357600080fd5b81019080805164010000000081111561004b57600080fd5b8281019050602081018481111561006157600080fd5b815185602082028301116401000000008211171561007e57600080fd5b5050929190505050336000806101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff16021790555060018060008060009054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000018190555060008090505b81518110156101bb5760026040805190810160405280848481518110151561015857fe5b90602001906020020151815260200160008152509080600181540180825580915050906001820390600052602060002090600202016000909192909190915060008201518160000155602082015181600101555050508080600101915050610134565b5050610cb5806101cc6000396000f3fe608060405260043610610088576000357c0100000000000000000000000000000000000000000000000000000000900480630121b93f1461008d578063013cf08b146100c85780632e4176cf1461011e5780635c19a95c14610175578063609ff1bd146101c65780639e7b8d61146101f1578063a3ec138d14610242578063e2ba53f0146102ec575b600080fd5b34801561009957600080fd5b506100c6600480360360208110156100b057600080fd5b8101908080359060200190929190505050610317565b005b3480156100d457600080fd5b50610101600480360360208110156100eb57600080fd5b81019080803590602001909291905050506104ba565b604051808381526020018281526020019250505060405180910390f35b34801561012a57600080fd5b506101336104ed565b604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390f35b34801561018157600080fd5b506101c46004803603602081101561019857600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610512565b005b3480156101d257600080fd5b506101db610938565b6040518082815260200191505060405180910390f35b3480156101fd57600080fd5b506102406004803603602081101561021457600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff1690602001909291905050506109b3565b005b34801561024e57600080fd5b506102916004803603602081101561026557600080fd5b81019080803573ffffffffffffffffffffffffffffffffffffffff169060200190929190505050610bfd565b60405180858152602001841515151581526020018373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200182815260200194505050505060405180910390f35b3480156102f857600080fd5b50610301610c5a565b6040518082815260200191505060405180910390f35b6000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020905060008160000154141515156103d7576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260148152602001807f486173206e6f20726967687420746f20766f746500000000000000000000000081525060200191505060405180910390fd5b8060010160009054906101000a900460ff1615151561045e576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600e8152602001807f416c726561647920766f7465642e00000000000000000000000000000000000081525060200191505060405180910390fd5b60018160010160006101000a81548160ff021916908315150217905550818160020181905550806000015460028381548110151561049857fe5b9060005260206000209060020201600101600082825401925050819055505050565b6002818154811015156104c957fe5b90600052602060002090600202016000915090508060000154908060010154905082565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1681565b6000600160003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002090508060010160009054906101000a900460ff161515156105dc576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260128152602001807f596f7520616c726561647920766f7465642e000000000000000000000000000081525060200191505060405180910390fd5b3373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610680576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252601e8152602001807f53656c662d64656c65676174696f6e20697320646973616c6c6f7765642e000081525060200191505060405180910390fd5b5b600073ffffffffffffffffffffffffffffffffffffffff16600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1614151561082757600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff1691503373ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1614151515610822576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260198152602001807f466f756e64206c6f6f7020696e2064656c65676174696f6e2e0000000000000081525060200191505060405180910390fd5b610681565b60018160010160006101000a81548160ff021916908315150217905550818160010160016101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055506000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002090508060010160009054906101000a900460ff161561091c578160000154600282600201548154811015156108f957fe5b906000526020600020906002020160010160008282540192505081905550610933565b816000015481600001600082825401925050819055505b505050565b6000806000905060008090505b6002805490508110156109ae578160028281548110151561096257fe5b90600052602060002090600202016001015411156109a15760028181548110151561098957fe5b90600052602060002090600202016001015491508092505b8080600101915050610945565b505090565b6000809054906101000a900473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff163373ffffffffffffffffffffffffffffffffffffffff16141515610a9d576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260288152602001807f4f6e6c79206368616972706572736f6e2063616e20676976652072696768742081526020017f746f20766f74652e00000000000000000000000000000000000000000000000081525060400191505060405180910390fd5b600160008273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060010160009054906101000a900460ff16151515610b62576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004018080602001828103825260188152602001807f54686520766f74657220616c726561647920766f7465642e000000000000000081525060200191505060405180910390fd5b6000600160008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060000154141515610bb357600080fd5b60018060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000206000018190555050565b60016020528060005260406000206000915090508060000154908060010160009054906101000a900460ff16908060010160019054906101000a900473ffffffffffffffffffffffffffffffffffffffff16908060020154905084565b60006002610c66610938565b815481101515610c7257fe5b90600052602060002090600202016000015490509056fea165627a7a7230582072f4679318cf41d402411ff4e56aa9084b22a14afb40f44471d4bd73c400d95b002900000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000003416c696365000000000000000000000000000000000000000000000000000000426f6200000000000000000000000000000000000000000000000000000000004b6576696e000000000000000000000000000000000000000000000000000000"
        data, _ := hexutil.Decode(bytecode)
        rpcClient, _ := rpc.Dial("http://localhost:20000")
        ethClient := ethclient.NewClient(rpcClient)
        privateKey, _ := crypto.HexToECDSA("8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63")
        publicKey := privateKey.Public()
        publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
        fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
        gasLimit := uint64(3000000)
        networkID, _ := ethClient.NetworkID(context.TODO())

        // get private nonce
        // 1. find private group
        priv := privacy.NewPrivacy(rpcClient)
        rootPrivacyGroup := priv.FindRootPrivacyGroup(participants)
        // 2. get private nonce
        privateNonce, _ := priv.PrivateNonce(fromAddress, rootPrivacyGroup)

        besutx := types.NewContractCreation(privateNonce, nil, gasLimit, big.NewInt(0), data, privateFrom, privateFor)
        besuSignedTx, _ := besutx.SignTx(networkID, privateKey)
        besuRawTxData, _ := rlp.EncodeToBytes(besuSignedTx)
        besuRawTxData = append(besuRawTxData[:1], besuRawTxData[4:]...) // KEVIN hack, remove redundant dust
        var txHash common.Hash
        rpcClient.CallContext(context.TODO(), &txHash, "eea_sendRawTransaction", hexutil.Encode(besuRawTxData))
        log.Println(txHash.Hex())
    }
    ```
    - 執行後回傳 transaction hash
    - 透過 priv_getTransactionReceipt 取得交易明細，記下 contract address 以利後續操作合約。

#### Besu Write Private Contract
- Write contract 時 transaction model 中的 Payload 由前一段說明方式產生
- 事先產生 payload，再執行 write Quorum private smart contract [範例](https://github.com/yenkuanlee/Enterprise-Ethereum/blob/master/besu/write/main.go)
    - 此範例執行 vote
    - transaction 中 receiptent 參數是 contract address
```go
package main

import (
	"context"
	"crypto/ecdsa"
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/ethereum/go-ethereum/rpc"

	"github.com/bsostech/go-besu/privacy"
	"github.com/bsostech/go-besu/types"
)

func main() {
	privateFromString := "A1aVtMxLCUHmBVHXoZzzBgPbW/wj5axDpW9X8l91SGo="
	privateFor1String := "Ko2bVqD+nNlNYL5EE7y3IdOnviftjiizpjRt+HTuFBs="
	privateFor2String := "k2zXEin4Ip/qBGlRkJejnGWdP9cjkK+DAvKNW31L2C8="
	privateFrom, _ := privacy.ToPublicKey(privateFromString)
	privateFor1, _ := privacy.ToPublicKey(privateFor1String)
	privateFor2, _ := privacy.ToPublicKey(privateFor2String)
	privateFor := [][]byte{privateFor1, privateFor2}
	participants := []*privacy.PublicKey{&privateFrom, &privateFor1, &privateFor2}

	rpcClient, _ := rpc.Dial("http://localhost:20000")
	ethClient := ethclient.NewClient(rpcClient)
	privateKey, _ := crypto.HexToECDSA("8f2a55949038a9610f50fb23b5883af3b4ecb3c3bb792cbcefbd1542c692be63")
	publicKey := privateKey.Public()
	publicKeyECDSA, _ := publicKey.(*ecdsa.PublicKey)
	fromAddress := crypto.PubkeyToAddress(*publicKeyECDSA)
	gasLimit := uint64(3000000)
	networkID, _ := ethClient.NetworkID(context.TODO())

	// get private nonce
	// 1. find private group
	priv := privacy.NewPrivacy(rpcClient)
	rootPrivacyGroup := priv.FindRootPrivacyGroup(participants)
	// 2. get private nonce
	privateNonce, _ := priv.PrivateNonce(fromAddress, rootPrivacyGroup)

	// besutx := types.NewContractCreation(privateNonce, nil, gasLimit, big.NewInt(0), data, privateFrom, privateFor)
	contractAddress := common.HexToAddress("0xaa56458ec6440e480f38be8de3a1abca3a95b7ea")
	data, _ := hexutil.Decode("0x0121b93f0000000000000000000000000000000000000000000000000000000000000002")
	besutx := types.NewTransaction(privateNonce, &contractAddress, nil, gasLimit, big.NewInt(0), data, privateFrom, privateFor)
	besuSignedTx, _ := besutx.SignTx(networkID, privateKey)
	besuRawTxData, _ := rlp.EncodeToBytes(besuSignedTx)
	besuRawTxData = append(besuRawTxData[:1], besuRawTxData[3:]...) // KEVIN hack, remove redundant dust
	var txHash common.Hash
	rpcClient.CallContext(context.TODO(), &txHash, "eea_sendRawTransaction", hexutil.Encode(besuRawTxData))
	log.Println(txHash.Hex())
}
```

#### Besu Read Private Contract
- 查詢區塊鏈狀態，透過 priv_call 實作
    - priv_call 需帶入一個 message 參數，包含 contract address，以及 read function 的參數打包。
    - priv_call 需額外帶入 privacy group
- 以下[範例](https://github.com/yenkuanlee/Enterprise-Ethereum/blob/master/besu/read/main.go)查詢當前最高票候選人
```go
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

	rpcClient, _ := rpc.Dial("http://localhost:20000")
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
```
- 以上範例執行結果是 Kevin (2 號候選人)

## BSOS 做了什麼？
BSOS 的核心技術 BridgeX，幫助企業快速導入區塊鏈。
![](https://i.imgur.com/NOndhR7.png)

###  BridgeX 架構
![](https://i.imgur.com/EYd34sH.png)

### BridgeX 讓區塊鏈真正在企業落地
- K8S 異地部署
- 使用者身份
    - KYC
    - DID
    - Token
- 私鑰安全管理
    - BridgeX Vault plugin 安全保存私鑰
    - 所有動要到私鑰的行為 (如簽名交易) 皆發生在 vault
    - 任何人無法從 vault 取得私鑰，包含使用者自己。
- 上鏈資訊管理
    - 區塊鏈不適合存大資料及隱私資料
    - BridgeX 獨特的 hash model，將上鏈資訊物件化，實作 hash 上鏈，以及加密功能。
- 鏈上資訊管理
    - transaction hash, contract address, contract info 等管理
- 豐富的智能合約庫
    - 導入 [Openzeppelin](https://openzeppelin.com/)
    - 聯盟治理合約至於創世區塊
    - 多項 ERC 系列實作
        - ERC20, ERC721, ERC725, ERC734, ERC735...
    - 開發企業應用相關智能合約 
- 點對點私密訊息
    - DID + PKI
- 訊息通知佇列
    - 私密訊息通知
    - 私交易通知給參與者
- 互操作性 (Interoperability)
    - Quorum and Quorum
    - Besu and Besu
    - Quorum and Besu
- 信任計算
    - 參考 [Hyperledger Avalon](https://www.hyperledger.org/use/avalon)

### BridgeX 微服務架構
![](https://i.imgur.com/Rzelq1H.png)

