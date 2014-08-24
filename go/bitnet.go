package bitnet

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/conformal/btcec"
	"github.com/conformal/btcnet"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
	log "github.com/golang/glog"
)

// Constants
const TokensPerSatoshi = uint64(1e3)
const TokensForAddressWithBalance = uint64(1e6)
const BitcoinSigMagic = "Bitcoin Signed Message:\n"
const MinConfForClaimTokens = 0

// Data structures
type BitcoinAddress string

func NewBitcoinAddress(str string) (*BitcoinAddress, error) {
	// TODO(ortutay): Validate address string.
	addr := (BitcoinAddress)(str)
	return &addr, nil
}

func (ba *BitcoinAddress) String() string {
	return string(*ba)
}

type SignableHasher interface {
	SignableHash() (string, error)
}

func CheckSig(sigStr string, hasher SignableHasher, pubKey *btcec.PublicKey) bool {
	sigBytes, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		return false
	}
	sig, err := btcec.ParseSignature(sigBytes, btcec.S256())
	if err != nil {
		return false
	}

	hash, err := hasher.SignableHash()
	if err != nil {
		log.Errorf("Unexpected error getting signable hash of %v: %v", hasher, err)
		return false
	}

	return sig.Verify([]byte(hash), pubKey)
}

func GetSig(hasher SignableHasher, privKey *btcec.PrivateKey) (string, error) {
	hash, err := hasher.SignableHash()
	if err != nil {
		log.Errorf("Unexpected error getting signable hash of %v: %v", hasher, err)
		return "", fmt.Errorf("couldn't get hash: %v", err)
	}

	sig, err := privKey.Sign([]byte(hash))
	if err != nil {
		return "", fmt.Errorf("couldn't sign: %v", err)
	}

	return base64.StdEncoding.EncodeToString(sig.Serialize()), nil
}

func GetSigBitcoin(hasher SignableHasher, privKey *btcec.PrivateKey, btcAddr string) (string, error) {
	hash, err := hasher.SignableHash()
	if err != nil {
		log.Errorf("Unexpected error getting signable hash of %v: %v", hasher, err)
		return "", fmt.Errorf("couldn't get hash: %v", err)
	}

	fullMessage := BitcoinSigMagic + hash
	compressed, err := isCompressed(privKey, btcAddr, netParams)
	if err != nil {
		return "", fmt.Errorf("couldn't check compression: %v", err)
	}

	sigBytes, err := btcec.SignCompact(btcec.S256(), privKey.ToECDSA(),
		btcwire.DoubleSha256([]byte(fullMessage)), compressed)
	if err != nil {
		return "", fmt.Errorf("couldn't sign compact: %v", err)
	}

	return base64.StdEncoding.EncodeToString(sigBytes), nil
}

type Section struct {
	// Expected headers:
	// - "datetime": ISO 8601 date/time
	// - "relayed-by": A list of tuples in the form (pubkey, sig), indicating the
	//    sequence and identities of the servers that have relayed this message.
	//    Sigatures are of the message hash as-received, ensuring the relay order
	//    cannot be forged after the fact, although it is possible for servers to
	//    omit their signature.
	// - "sender-public-key": Public key of the sender.
	// - "sender-sig": Signature of sender corresponding to "sender-public-key".
	// - "receiver-public-key": Public key of the intended recepient. Purely
	//    advisory.
	Headers map[string]string
	Body    string
}

type Message struct {
	Plaintext Section
	Encrypted string
}

type Query struct {
	MessageHash []string          // If set, match on the message hash.
	Headers     map[string]string // If set, do equality check on message headers.
	// TODO(ortutay): We will want more advanced querying in the future, but for
	// now this will be enough.
}

type TokenTransaction struct {
	Challenge string // Challenge from the server.
	Amount    int64  // Amount to spend. Use -1 to indicate server decides.
	Sig       string // Signature with private key holding the tokens.
}

// Token management
// TODO(ortutay): nonce/sig on each Args/Reply struct? generally, want some
// system for server auth
// TODO(ortutay): BIP 70
type RequestPaymentDetailsArgs struct {
	Amount int64
}

type RequestPaymentDetailsReply struct {
	Address BitcoinAddress // Address where server requests payment.
	Sig     string         // Signature by the server's private key.
}

type BuyTokensArgs struct {
	RawTx  string // Raw bitcoin transaction that pays for the tokens.
	PubKey string // Public key where the sever sends tokens.
}

type BuyTokensReply struct {
}

type ClaimTokensArgs struct {
	Challenge      string // Challenge from the server.
	BitcoinAddress string // Bitcoin address used to sign.
	PubKey         string // Public key where the sever sends tokens.
	Sig            string // Signature of the challenge and public key.
}

func (a *ClaimTokensArgs) SignableHash() (string, error) {
	var buf bytes.Buffer
	buf.WriteString(a.Challenge)
	buf.WriteString(a.BitcoinAddress)
	buf.WriteString(a.PubKey)
	return sha256Hex(buf.Bytes())
}

type ClaimTokensReply struct {
}

type ChallengeArgs struct {
}

type ChallengeReply struct {
	Challenge string // Challenge to be used for signature.
}

type GetBalanceArgs struct {
	Challenge string // Challenge from the server.
	PubKey    string // Public key to get balance for.
	Sig       string // Signature of the args.
}

func (a *GetBalanceArgs) SignableHash() (string, error) {
	var buf bytes.Buffer
	buf.WriteString(a.Challenge)
	buf.WriteString(a.PubKey)
	return sha256Hex(buf.Bytes())
}

type GetBalanceReply struct {
	Balance uint64
}

type BurnArgs struct {
	Tokens TokenTransaction
}

type BurnReply struct {
}

// Sending and getting messages
type StoreMessageArgs struct {
	Tokens  TokenTransaction
	Message Message
}

type StoreMessageReply struct {
}

type ListMessagesArgs struct {
	Tokens TokenTransaction
	Query  Query
}

type ListMessagesReply struct {
	MessageHashes  []string
	MessageHeaders []map[string]string
	Sig            string
}

type GetMessagesArgs struct {
	Tokens TokenTransaction
	Query  Query
}

type GetMessagesReply struct {
	Messages []Message
	Sig      string
}

func sha256Hex(data []byte) (string, error) {
	h := sha256.New()
	_, err := h.Write(data)
	if err != nil {
		return "", err
	}
	b := h.Sum([]byte{})
	return hex.EncodeToString(b), nil
}

func isCompressed(privKey *btcec.PrivateKey, addr string, netParams *btcnet.Params) (bool, error) {
	btcPubKey := (btcec.PublicKey)(privKey.PublicKey)
	serCompressed := btcPubKey.SerializeCompressed()
	compressedAddr, err := btcutil.NewAddressPubKey(serCompressed, netParams)
	if err != nil {
		return false, err
	}
	return compressedAddr.EncodeAddress() == addr, nil
}
