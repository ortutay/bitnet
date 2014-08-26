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
	"strconv"
)

// Constants
const TokensPerSatoshi = uint64(1e3)
const TokensForAddressWithBalance = uint64(1e6)
const BitcoinSigMagic = "Bitcoin Signed Message:\n"
const MinConfForClaimTokens = 0
const DefaultBurnAmount = 10

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
	SignableHash() ([]byte, error)
}

func CheckSig(sigStr string, hasher SignableHasher, pubKey *btcec.PublicKey) bool {
	sigBytes, err := base64.StdEncoding.DecodeString(sigStr)
	if err != nil {
		return false
	}
	sig, err := btcec.ParseSignature(sigBytes, btcec.S256())
	if err != nil {
		log.Warningf("Couldn't parse signature %q: %v", sigStr, err)
		return false
	}

	hash, err := hasher.SignableHash()
	if err != nil {
		// This should never be reached, as the called functions don't return errors
		log.Errorf("Unexpected error getting signable hash of %v: %v", hasher, err)
		return false
	}

	return sig.Verify(hash, pubKey)
}

func GetSig(hasher SignableHasher, privKey *btcec.PrivateKey) (string, error) {
	hash, err := hasher.SignableHash()
	if err != nil {
		log.Errorf("Unexpected error getting signable hash of %v: %v", hasher, err)
		return "", fmt.Errorf("couldn't get hash: %v", err)
	}

	sig, err := privKey.Sign(hash)
	if err != nil {
		return "", fmt.Errorf("couldn't sign: %v", err)
	}

	return base64.StdEncoding.EncodeToString(sig.Serialize()), nil
}

func GetSigBitcoin(hasher SignableHasher, privKey *btcec.PrivateKey, btcAddr string, netParams *btcnet.Params) (string, error) {
	hash, err := hasher.SignableHash()
	if err != nil {
		log.Errorf("Unexpected error getting signable hash of %v: %v", hasher, err)
		return "", fmt.Errorf("couldn't get hash: %v", err)
	}

	fullMessage := BitcoinSigMagic + hex.EncodeToString(hash)
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
	// - "type": If set, indicates that this message conforms to a standard
	//    message type. Examples include a payment request, a partially signed
	//    multisig transaction, or a coinjoin transaction. The server may perform
	//    additional validation on known types.
	// - "relayed-by": A list of tuples in the form (pubkey, sig), indicating the
	//    sequence and identities of the servers that have relayed this message.
	//    Sigatures are of the message hash as-received, ensuring the relay order
	//    cannot be forged after the fact, although it is possible for servers to
	//    omit their signature.
	// - "sender-public-key": Public key of the sender.
	// - "sender-sig": Signature of sender corresponding to "sender-public-key".
	// - "receiver-public-key": Public key of the intended recepient. If there is
	//    an encrypted section, the corresponding private key can decrypt it.
	Headers map[string]string
	Body    string
}

type Message struct {
	Plaintext Section
	Encrypted string
}

func (m *Message) SignableHash() ([]byte, error) {
	return nil, nil
}

func (m *Message) IsValid() (bool, error) {
	return false, nil
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
	PubKey    string // Public key storing the tokens.
	Sig       string // Signature with private key holding the tokens.
}

func (t *TokenTransaction) SignableHash() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(t.Challenge)
	buf.WriteString(strconv.FormatInt(t.Amount, 10))
	return doSHA256(buf.Bytes())
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
	PubKey         string // Public key where the sever sends tokens.
	BitcoinAddress string // Bitcoin address used to sign.
	Sig            string // Bitcoin signature of the challenge and public key.
}

func (a *ClaimTokensArgs) SignableHash() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(a.Challenge)
	buf.WriteString(a.PubKey)
	buf.WriteString(a.BitcoinAddress)
	return doSHA256(buf.Bytes())
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

func (a *GetBalanceArgs) SignableHash() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteString(a.Challenge)
	buf.WriteString(a.PubKey)
	return doSHA256(buf.Bytes())
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

func doSHA256(data []byte) ([]byte, error) {
	h := sha256.New()
	_, err := h.Write(data)
	if err != nil {
		return nil, err
	}
	b := h.Sum([]byte{})
	return b, nil
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
