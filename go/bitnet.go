package bitnet

import (
	"bitbucket.org/ortutay/bitnet/util"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/conformal/btcec"
	"github.com/conformal/btcnet"
	"github.com/conformal/btcutil"
	"github.com/conformal/btcwire"
	log "github.com/golang/glog"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Constants
const TokensPerSatoshi = uint64(1e6)
const TokensForAddressWithBalance = uint64(1e9)
const BitcoinSigMagic = "Bitcoin Signed Message:\n"
const MinConfForClaimTokens = 0
const DefaultBurnAmount = 10

const assumedBitcoinPrice = uint64(500) // Use approximate rate of $500/BTC
const satoshisPerBitcoin = uint64(1e8)
const storeMessageUSDPrice = float64(.00000001) // 1 penny stores 1M messages
const StoreMessageTokenPrice = uint64(storeMessageUSDPrice *
	1 / float64(assumedBitcoinPrice) *
	float64(satoshisPerBitcoin) *
	float64(TokensPerSatoshi))

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
	// - "datetime": RFC 3339 date/time
	// - "type": If set, indicates that this message conforms to a standard
	//    message type. Examples include a payment request, a partially signed
	//    multisig transaction, or a coinjoin transaction. The server may perform
	//    additional validation on known types.
	// - "relayed-by": A list of tuples in the form (pubkey, sig), indicating the
	//    sequence and identities of the servers that have relayed this message.
	//    Sigatures are of the message hash as-received, ensuring the relay order
	//    cannot be forged after the fact, although it is possible for servers to
	//    omit their signature.
	// - "sender-pubkey": Public key of the sender.
	// - "sender-sig": Signature of sender corresponding to "sender-public-key".
	// - "receiver-pubkey": Public key of the intended recepient. If there is
	//    an encrypted section, the corresponding private key can decrypt it.
	// - "expires-datetime": Tells the server to delete the message after a
	//    given date/time.
	// - "expires-pubkey": Tells the server to delete the message after a given
	//    public key(s) has gotten it.
	Headers map[string][]string
	Body    string
}

func (s *Section) AddHeader(field string, value string) {
	if s.Headers == nil {
		s.Headers = make(map[string][]string)
	}
	if _, ok := s.Headers[field]; !ok {
		s.Headers[field] = make([]string, 0)
	}
	s.Headers[field] = append(s.Headers[field], value)
}

type Message struct {
	Plaintext Section
	Encrypted string
}

func (m *Message) SignableHash() ([]byte, error) {
	h := sha256.New()

	var headerFields []string
	for field, _ := range m.Plaintext.Headers {
		if field == "sender-sig" {
			continue
		}
		headerFields = append(headerFields, field)
	}
	sort.Strings(headerFields)
	for _, field := range headerFields {
		h.Write([]byte(field))
		h.Write([]byte(strings.Join(m.Plaintext.Headers[field], "")))
	}

	h.Write([]byte(m.Plaintext.Body))
	h.Write([]byte(m.Encrypted))

	return h.Sum([]byte{}), nil
}

func validateDatetime(datetimes []string) error {
	for _, datetime := range datetimes {
		if _, err := time.Parse(time.RFC3339, datetime); err != nil {
			return err
		}
	}
	return nil
}

func validatePubKey(pubKeys []string) error {
	fmt.Printf("validate pubkey %v\n", pubKeys)
	for _, pubKeyHex := range pubKeys {
		if _, err := util.PubKeyFromHex(pubKeyHex); err != nil {
			return err
		}
	}
	return nil
}

func (m *Message) Validate() error {
	fmt.Printf("validate %v\n", m)

	// Validate plaintext headers
	for field, value := range m.Plaintext.Headers {
		switch field {
		case "datetime", "expires-datetime":
			if err := validateDatetime(value); err != nil {
				return fmt.Errorf("invalid %s: %v", field, err)
			}
		case "sender-pubkey", "receiver-pubkey", "expires-pubkey":
			if err := validatePubKey(value); err != nil {
				return fmt.Errorf("invalid %s", field)
			}
		}
	}

	// Public keys fields have been validated, check signatures
	for field, _ := range m.Plaintext.Headers {
		switch field {
		case "sender-sig":
			senderPubKeys, ok := m.Plaintext.Headers["sender-pubkey"]
			if !ok {
				return errors.New("got sender-sig, but missing sender-pubkey")
			}
			senderSigs := m.Plaintext.Headers["sender-sig"]
			if len(senderPubKeys) != len(senderSigs) {
				return fmt.Errorf(
					"mismatched sender-pubkey and sender-sig lengths: %d = %d",
					len(senderPubKeys), len(senderSigs))
			}
			for i, pubKeyHex := range senderPubKeys {
				pubKey, err := util.PubKeyFromHex(pubKeyHex)
				if err != nil {
					return errors.New("unexpected invalid pubkey")
				}
				if !CheckSig(senderSigs[i], m, pubKey) {
					return fmt.Errorf("invalid sig/pubkey: %q %q", senderSigs[i], pubKeyHex)
				}
			}
		}
	}

	return nil
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
