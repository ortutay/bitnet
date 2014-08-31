package main

import (
	"github.com/gorilla/mux"
	"github.com/ortutay/bitnet"
	"github.com/ortutay/bitnet/util"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"github.com/conformal/btcec"
	"github.com/conformal/btcnet"
	"github.com/conformal/btcscript"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
	log "github.com/golang/glog"
	"github.com/gorilla/rpc"
	"github.com/gorilla/rpc/json"
	"net/http"
	"time"
)

const sigMagic = "Bitcoin Signed Message:\n"

var testnet = flag.Bool("testnet", true, "Use testnet")
var allowFreeTokens = flag.Bool("allow_free_tokens", true, "Allow users to get free tokens")
var addr = flag.String("addr", ":8555", "Address to listen on")

type BitnetService struct {
	Bitcoin         Bitcoin
	Address         bitnet.BitcoinAddress
	Datastore       *bitnet.Datastore
	ActiveNetParams *btcnet.Params
}

func NewBitnetServiceOnHelloBlock(address bitnet.BitcoinAddress) *BitnetService {
	hb := new(HelloBlock)
	if *testnet {
		hb.SetNetwork(Testnet3)
	} else {
		hb.SetNetwork(Mainnet)
	}
	bitnet := BitnetService{
		Address:         address,
		Datastore:       bitnet.NewDatastore(),
		Bitcoin:         hb,
		ActiveNetParams: &btcnet.TestNet3Params,
	}
	return &bitnet
}

func main() {
	flag.Parse()
	log.Infof("Bitnet RPC listening on %v...", *addr)

	// Start Bitnet RPC server
	// TODO(ortutay): Do not use static addresses.
	var btcAddr bitnet.BitcoinAddress
	if *testnet {
		btcAddr = "mrvdXP7dNodDu9YcdrFWzfXomnWNvASGnb"
	} else {
		btcAddr = "1K4aU4iVk5JR1TNhTSxR3LgpEdBWSyb7d4"
	}
	bitnet := NewBitnetServiceOnHelloBlock(btcAddr)
	log.Infof("Bitnet service %v", bitnet)
	server := rpc.NewServer()
	server.RegisterCodec(json.NewCodec(), "application/json")
	server.RegisterService(bitnet, "Bitnet")
	http.Handle("/bitnetRPC", server)
	go http.ListenAndServe(*addr, nil)

	// Start HTTP server
	r := mux.NewRouter()
	r.HandleFunc("/", HomeHandler)
	http.Handle("/", r)

	port := fmt.Sprintf(":%d", 8080)
	log.Infof("HTTP listening on %v...", port)
	http.ListenAndServe(port, nil)
}

func netParams() *btcnet.Params {
	if *testnet {
		return &btcnet.TestNet3Params
	} else {
		return &btcnet.MainNetParams
	}
}

func (b *BitnetService) BuyTokens(r *http.Request, args *bitnet.BuyTokensArgs, reply *bitnet.BuyTokensReply) error {
	defer log.Flush()
	log.Infof("Handling BuyTokens %v\n", args)
	txData, err := hex.DecodeString(args.RawTx)
	if err != nil {
		return errors.New("couldn't decode raw transaction")
	}
	tx, err := btcutil.NewTxFromBytes(txData)
	if err != nil {
		return fmt.Errorf("couldn't decode tx: %v", err)
	}
	log.Infof("got tx: %v\n", tx)
	value := uint64(0)
	for _, out := range tx.MsgTx().TxOut {
		scriptClass, addresses, _, err := btcscript.ExtractPkScriptAddrs(
			out.PkScript, netParams())
		if err != nil {
			log.Errorf("Couldn't decode %v: %v", out.PkScript, err)
			return errors.New("couldn't decode transaction")
		}
		if scriptClass != btcscript.PubKeyHashTy {
			continue
		}
		if addresses[0].String() != b.Address.String() {
			continue
		}
		value += uint64(out.Value)
	}
	numTokens := value * bitnet.TokensPerSatoshi
	log.Infof("Tx value to us: %v -> %v tokens\n", value, numTokens)

	txHash, err := b.Bitcoin.SendRawTransaction(args.RawTx)
	if err != nil {
		return errors.New("bitcoin network did not accept transaction")
	}
	log.Infof("Successfully submitted transaction, ID: %v\n", txHash)

	pubKey, err := util.PubKeyFromHex(args.PubKey)
	if err != nil {
		return errors.New("couldn't decode public key")
	}

	// TODO(ortutay): Getting an error here is bad, because we have already
	// submitted the client's transaction. We should have more handling around
	// this case.
	if err := b.Datastore.AddTokens(pubKey, int64(numTokens)); err != nil {
		log.Errorf("Couldn't add tokens in datastore %v", err)
		return errors.New("Transaction was accepted, but error while crediting tokens. Please report.")
	}

	return nil
}

func (b *BitnetService) ClaimTokens(r *http.Request, args *bitnet.ClaimTokensArgs, reply *bitnet.ClaimTokensReply) error {
	defer log.Flush()
	log.Infof("ClaimTokens(%v)", args)

	tokensPubKey, err := util.PubKeyFromHex(args.PubKey)
	if err != nil {
		return errors.New("couldn't decode public key")
	}

	if *allowFreeTokens && args.Sig == "claimfree" {
		if err := b.Datastore.AddTokens(tokensPubKey, int64(bitnet.TokensForAddressWithBalance)); err != nil {
			log.Errorf("Couldn't add tokens in datastore %v", err)
			return errors.New("Signature was accepted, but error while crediting tokens.")
		}
		return nil
	}

	// Verify signature.
	fullMessage := bitnet.BitcoinSigMagic + hex.EncodeToString(args.SignableHash())

	sigBytes, err := base64.StdEncoding.DecodeString(args.Sig)
	if err != nil {
		log.Errorf("Couldn't decode signature for %v: %v", args, err)
		return errors.New("couldn't verify signature")
	}
	hash := btcwire.DoubleSha256([]byte(fullMessage))
	pubKey, wasCompressed, err := btcec.RecoverCompact(btcec.S256(), sigBytes, hash)

	btcPubKey := (*btcec.PublicKey)(pubKey)
	var serializedBytes []byte
	if wasCompressed {
		serializedBytes = btcPubKey.SerializeCompressed()
	} else {
		serializedBytes = btcPubKey.SerializeUncompressed()
	}
	btcAddrPK, err := btcutil.NewAddressPubKey(serializedBytes, netParams())
	if err != nil {
		log.Errorf("Couldn't create bitcoin address for %v %v: %v", serializedBytes, args, err)
		return errors.New("couldn't verify signature")
	}
	if btcAddrPK.EncodeAddress() != args.BitcoinAddress {
		return errors.New("invalid signature")
	}

	// Verify that challenge is valid.
	if !b.Datastore.HasChallenge(args.Challenge) {
		return errors.New("invalid challenge")
	}
	expires, err := b.Datastore.GetChallengeExpiration(args.Challenge)
	if err != nil {
		log.Errorf("Couldn't get challenge %v: %v", args.Challenge, err)
		return errors.New("server error")
	}
	expired := expires < time.Now().Unix()
	if err := b.Datastore.DeleteChallenge(args.Challenge); err != nil {
		log.Errorf("Couldn't delete challenge %v: %v", args.Challenge, err)
		if !expired {
			return errors.New("server error")
		}
	}
	if expired {
		return errors.New("challenge expired, retry with new challenge")
	}

	btcAddr, err := btcutil.DecodeAddress(args.BitcoinAddress, b.ActiveNetParams)
	if err != nil {
		log.Errorf("Unexpected error decoding address %q: %v",
			args.BitcoinAddress, err)
		return errors.New("couldn't decode bitcoin address")
	}
	received, err := b.Bitcoin.GetTotalReceived(btcAddr, bitnet.MinConfForClaimTokens)
	if err != nil {
		log.Errorf("Error while getting bitcoin balance for %v: %v", btcAddr, err)
		return errors.New("server error")
	}
	log.Infof("received for %v: %v", btcAddr.EncodeAddress(), received)
	if received == 0 {
		return errors.New("signing address has never received bitcoin")
	}

	// TODO(ortutay): Check that address has not been used.
	pkHashAddr, err := bitnet.NewBitcoinAddress(args.BitcoinAddress)
	if err != nil {
		// We have already validated the address, so we should never reach this.
		log.Errorf("Invalid address reach unexpectedly for %q", args.BitcoinAddress)
		return errors.New("invalid bitcoin address")
	}
	if b.Datastore.HasUsedAddress(pkHashAddr) {
		return errors.New("already credited tokens for this address")
	}

	if err := b.Datastore.AddTokens(tokensPubKey, int64(bitnet.TokensForAddressWithBalance)); err != nil {
		log.Errorf("Couldn't add tokens in datastore %v", err)
		return errors.New("Signature was accepted, but error while crediting tokens.")
	}

	if err := b.Datastore.StoreUsedAddress(pkHashAddr); err != nil {
		log.Errorf("Error while noting address use: %v", err)
		// Do not return error, since we have credited the tokens.
	}

	return nil
}

func (b *BitnetService) Challenge(r *http.Request, args *bitnet.ChallengeArgs, reply *bitnet.ChallengeReply) error {
	defer log.Flush()
	// TODO(ortutay): This is susceptible to DOS attack in two ways:
	// 1) Filling the datastore with lots of challenge strings.
	// 2) Exhausting entropy on the system.
	// Mitigation possibilities:
	// - Add expiration to challenge string, and regularly purge the datastore.
	// - When system lacks entropy, we could make a call to trusted external
	//   source of entropy, like random.org. This is undesireable and a potential
	//   security hole.
	// - Require tokens to generate a challenge. This is undeseriable, since
	//   challenge is used for the ClaimTokens method.
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	if err != nil {
		log.Errorf("Couldn't generate challenge: %v", err)
		return errors.New("couldn't generate challenge")
	}
	challenge := hex.EncodeToString(buf)
	if err := b.Datastore.StoreChallenge(challenge); err != nil {
		log.Errorf("Couldn't store challenge: %v", err)
		return errors.New("couldn't generate challenge")
	}
	reply.Challenge = challenge
	return nil
}

func (b *BitnetService) GetBalance(r *http.Request, args *bitnet.GetBalanceArgs, reply *bitnet.GetBalanceReply) error {
	defer log.Flush()
	log.Infof("GetBalance(%v)", args)
	pubKey, err := util.PubKeyFromHex(args.PubKey)
	if err != nil {
		return errors.New("couldn't decode public key")
	}

	if !bitnet.CheckSig(args.Sig, args, pubKey) {
		return errors.New("invalid signature")
	}

	balance, err := b.Datastore.GetNumTokens(pubKey)
	if err != nil {
		log.Errorf("Couldn't get number of tokens for %v: %v", pubKey, err)
		return errors.New("server error")
	}
	reply.Balance = balance

	return nil
}

func (b *BitnetService) checkTokens(pubKey *btcec.PublicKey, tokens *bitnet.TokenTransaction) (int64, error) {
	defer log.Flush()
	if !bitnet.CheckSig(tokens.Sig, tokens, pubKey) {
		return 0, errors.New("invalid signature on tokens")
	}
	numTokens, err := b.Datastore.GetNumTokens(pubKey)
	if err != nil {
		log.Errorf("Error on GetNumTokens(%v): %v", pubKey, err)
		return 0, errors.New("server error")
	}
	amount := tokens.Amount
	if amount == -1 {
		amount = bitnet.DefaultBurnAmount
	} else if amount < -1 {
		return 0, errors.New("invalid burn amount")
	}
	if numTokens < uint64(amount) {
		return 0, errors.New("insufficient balance")
	}
	return amount, nil
}

func (b *BitnetService) Burn(r *http.Request, args *bitnet.BurnArgs, reply *bitnet.BurnReply) error {
	defer log.Flush()
	log.Infof("Burn(%v)", args)
	pubKey, err := util.PubKeyFromHex(args.Tokens.PubKey)
	if err != nil {
		return errors.New("couldn't decode public key")
	}

	amount, err := b.checkTokens(pubKey, &args.Tokens)
	if err != nil {
		return err
	}
	if err := b.Datastore.AddTokens(pubKey, -amount); err != nil {
		log.Errorf("Error on AddTokens(%v): %v", err)
	}

	return nil
}

func (b *BitnetService) StoreMessage(r *http.Request, args *bitnet.StoreMessageArgs, reply *bitnet.StoreMessageReply) error {
	defer log.Flush()
	log.Infof("StoreMessage(%v)", args)

	pubKey, err := util.PubKeyFromHex(args.Tokens.PubKey)
	if err != nil {
		return errors.New("couldn't decode public key")
	}

	amount, err := b.checkTokens(pubKey, &args.Tokens)
	if err != nil {
		return err
	}

	if err := args.Message.Validate(); err != nil {
		return err
	}

	if err := b.Datastore.StoreMessage(&args.Message); err != nil {
		log.Errorf("Error on StoreMessage(%v): %v", args.Message, err)
		return errors.New("server error")
	}

	if err := b.Datastore.AddTokens(pubKey, -amount); err != nil {
		log.Errorf("Error on AddTokens(%v): %v", err)
	}

	return nil
}

func (b *BitnetService) GetMessages(r *http.Request, args *bitnet.GetMessagesArgs, reply *bitnet.GetMessagesReply) error {
	defer log.Flush()
	log.Infof("GetMessages(%v)", args)
	if err := args.Query.Validate(); err != nil {
		return fmt.Errorf("invalid query: %v", err)
	}
	msgs, err := b.Datastore.GetMessages(&args.Query)
	if err != nil {
		log.Errorf("Error on GetMesssages(%v): %v", args.Query, err)
		return errors.New("server error")
	}
	reply.Messages = make([]bitnet.Message, len(msgs))
	for i, msg := range msgs {
		reply.Messages[i] = *msg
	}
	return nil
}
