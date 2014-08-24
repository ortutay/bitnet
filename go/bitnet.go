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
)

// Constants
const TokensPerSatoshi = int64(1e6)
const TokensForAddressWithBalance = int64(1e12)
const BitcoinSigMagic = "Bitcoin Signed Message:\n"

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

func SignArgsBitcoin(hasher SignableHasher, privKey *btcec.PrivateKey, btcAddr string, netParams *btcnet.Params) (string, error) {
	signable, err := hasher.SignableHash()
	if err != nil {
		return "", fmt.Errorf("couldn't get hash: %v", err)
	}

	fullMessage := BitcoinSigMagic + signable
	hash := btcwire.DoubleSha256([]byte(fullMessage))
	compressed, err := isCompressed(privKey, btcAddr, netParams)
	if err != nil {
		return "", fmt.Errorf("couldn't check compression: %v", err)
	}

	sigBytes, err := btcec.SignCompact(btcec.S256(), privKey.ToECDSA(), hash, compressed)
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
	PubKey         string // Public key where the sever sends tokens.
	BitcoinAddress string // Bitcoin address used to sign.
	Sig            string // Bitcoin signature of the challenge and public key.
}

func (a *ClaimTokensArgs) SignableHash() (string, error) {
	var buf bytes.Buffer
	buf.WriteString(a.Challenge)
	buf.WriteString(a.PubKey)
	buf.WriteString(a.BitcoinAddress)
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
	Challenge string
	PubKey    string
}

type GetBalanceReply struct {
	Balance int64
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
