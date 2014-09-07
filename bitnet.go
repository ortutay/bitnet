package bitnet

// bitnet contains the RPC argument and reply data structure for the bitnet
// service.
//
// The basic interaction between the client and server is getting and storing
// messages. A message has a plain-text section and an encrypted section, and
// the plain-text section is further broken into headers and the body. Getting
// messages is done via a query, which contains filters on various headers in
// the messages.
//
// For anti-spam, the server may optionally charge some number of
// tokens for each of these actions. Tokens can be purchased from the server
// through a bitcoin transaction, or they can be claimed by signing a message
// that has received bitcoins.

import (
	"bitbucket.org/ortutay/bitnet/util"
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
	"math/big"
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
const MaxMessageBytes = 100000 // 100KB

// TODO(ortutay): We may want to tweak these constants, and/or make them flag
// configurable.
// Calculate a price in tokens for storing messages.
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

// Structs implementing this interface provide a hash of their data for signing
// by a private key.
type SignableHasher interface {
	SignableHash() []byte
}

// CheckSig checks a signature against a public key.
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

	return sig.Verify(hasher.SignableHash(), pubKey)
}

// GetSig generates a signature from a private key.
func GetSig(hasher SignableHasher, privKey *btcec.PrivateKey) (string, error) {
	sig, err := privKey.Sign(hasher.SignableHash())
	if err != nil {
		return "", fmt.Errorf("couldn't sign: %v", err)
	}
	return base64.StdEncoding.EncodeToString(sig.Serialize()), nil
}

// GetSigBitcoin generates a Bitcoin style signature from a private key.
func GetSigBitcoin(hasher SignableHasher, privKey *btcec.PrivateKey, btcAddr string, netParams *btcnet.Params) (string, error) {
	fullMessage := BitcoinSigMagic + hex.EncodeToString(hasher.SignableHash())
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

// Section is part of a Message.
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
	// - "from-pubkey": Public key of the sender.
	// - "from-sig": Signature of sender corresponding to "from-pubkey".
	// - "to-pubkey": Public key of the intended recepient. If there is
	//    an encrypted section, the corresponding private key can decrypt it.
	// - "expires-datetime": Tells the server to delete the message after a
	//    given date/time.
	// - "expires-pubkey": Tells the server to delete the message after a given
	//    public key(s) has gotten it.
	// Reserved header:
	// - "message-hash": SHA-256 hash of the message, hex encoded. This field
	//    must not be set, and is instead calculated on the fly as needed.
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

// Message is the core data structure. It is what clients send and receive to
// communicate.
type Message struct {
	Plaintext Section
	Encrypted string
}

func (m *Message) SignableHash() []byte {
	h := sha256.New()

	var headerFields []string
	for field, _ := range m.Plaintext.Headers {
		if field == "from-sig" {
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

	return h.Sum([]byte{})
}

func (m *Message) HashHex() string {
	return hex.EncodeToString(m.SignableHash())
}

func (m *Message) Size() int {
	size := 0
	for field, value := range m.Plaintext.Headers {
		size += len(field)
		for _, v := range value {
			size += len(v)
		}
	}
	size += len(m.Plaintext.Body)
	size += len(m.Encrypted)
	return size
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
	for _, pubKeyHex := range pubKeys {
		if _, err := util.PubKeyFromHex(pubKeyHex); err != nil {
			return err
		}
	}
	return nil
}

// Check recognized header fields, and return error if they are not in the
// expected format.
func (m *Message) Validate() error {
	// TODO(ortutay): Add a max expires-datetime?

	if m.Size() > MaxMessageBytes {
		return fmt.Errorf("message size exceeds maximum: %d > %d", m.Size(), MaxMessageBytes)
	}

	// Validate plaintext headers
	for field, value := range m.Plaintext.Headers {
		if strings.Contains(field, " ") {
			return fmt.Errorf("invalid header field %q contains space", field)
		}
		switch field {
		case "datetime", "expires-datetime":
			if err := validateDatetime(value); err != nil {
				return fmt.Errorf("invalid %s: %v", field, err)
			}
		case "from-pubkey", "to-pubkey", "expires-pubkey":
			if err := validatePubKey(value); err != nil {
				return fmt.Errorf("invalid %s", field)
			}
		case "message-hash":
			return fmt.Errorf("header %s is reserved", field)
		}
	}

	// Public keys fields have been validated, check signatures
	for field, _ := range m.Plaintext.Headers {
		switch field {
		case "from-sig":
			senderPubKeys, ok := m.Plaintext.Headers["from-pubkey"]
			if !ok {
				return errors.New("got from-sig, but missing from-pubkey")
			}
			senderSigs := m.Plaintext.Headers["from-sig"]
			if len(senderPubKeys) != len(senderSigs) {
				return fmt.Errorf(
					"mismatched from-pubkey and from-sig lengths: %d = %d",
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

// Query represents a filter that matches based on the message headers. The
// supported operators are operators =, !=, <, >, <= and >=.
//
// Examples:
//
//   Headers["some-field ="] = "value"
//   Headers["some-field !="] = "value"
//   Headers["some-field >="] = "value"
//   Headers["some-field"] = "value"    (= is assumed if no operator is given)
//
// The = and != operators will do a string comparison on the values.
// The <, >, <=, >= operators will attempt to convert both strings into
// numbers, and do a numerical comparison.
//
// TODO(ortutay): We can use gt, lt, gte, lte to indicate string order
// comparison.
// TODO(ortutay): We can use the ~ operator to indicate a hex-encoded Blooom
// filter.
type Query struct {
	Headers map[string]string
}

func getFieldAndOp(key string) (string, string, error) {
	s := strings.Split(key, " ")
	if len(s) > 2 {
		return "", "", fmt.Errorf("invalid key %q contains over 2 spaces", key)
	}
	var op string
	if len(s) == 1 {
		op = "="
	} else {
		op = s[1]
	}
	return s[0], op, nil
}

func (q *Query) Validate() error {
	for key, _ := range q.Headers {
		_, op, err := getFieldAndOp(key)
		if err != nil {
			return err
		}
		switch op {
		case "=", "!=", "<", ">", "<=", ">=":
			continue
		default:
			return fmt.Errorf("unhandled operator: %q", op)
		}
	}
	return nil
}

// Matches returns true if a Message matches a Query.
func (q *Query) Matches(msg *Message) bool {
	if err := q.Validate(); err != nil {
		log.Errorf("Invalid query %v: %v", q, err)
		return false
	}
	msgHash := msg.HashHex()
	for key, target := range q.Headers {
		matches := false
		field, op, _ := getFieldAndOp(key)
		var values []string
		var ok bool
		if field == "message-hash" {
			ok = true
			values = make([]string, 1)
			values[0] = msgHash
		} else {
			values, ok = msg.Plaintext.Headers[field]
		}

		if field == "datetime" {
			timestamps := make([]string, len(values))
			for i, value := range values {
				t, err := time.Parse(time.RFC3339, value)
				if err == nil {
					timestamps[i] = strconv.FormatInt(t.Unix(), 10)
				}
			}
			t, err := time.Parse(time.RFC3339, target)
			if err == nil {
				target = strconv.FormatInt(t.Unix(), 10)
			}
			values = timestamps
		}

		switch op {
		case "=":
			if !ok && target != "" {
				return false
			}
			for _, value := range values {
				if target == value {
					matches = true
					continue
				}
			}
		case "!=":
			if !ok && target == "" {
				continue
			}
			for _, value := range values {
				if target != value {
					matches = true
					continue
				}
			}
		case "<", ">", "<=", ">=":
			// Try comparing as rational number
			var targetBigRat big.Rat
			_, validAsRat := targetBigRat.SetString(target)
			if validAsRat {
				for _, value := range values {
					var valueBigRat big.Rat
					_, iterValidAsRat := valueBigRat.SetString(value)
					if !iterValidAsRat {
						continue
					}
					cmp := valueBigRat.Cmp(&targetBigRat)
					switch {
					// value < target
					case cmp == -1 && (op == "<" || op == "<="):
						matches = true

					// value = target
					case cmp == 0 && (op == "=" || op == "<=" || op == ">="):
						matches = true

					// value > target
					case cmp == 1 && (op == ">" || op == ">="):
						matches = true
					}
				}
			}
		}
		if !matches {
			return false
		}
	}
	return true
}

// The Challenge RPC is used by the client to request a challenge string.
// Challenge strings are used in signatures, to prevent replay attacks.
type ChallengeArgs struct {
}

type ChallengeReply struct {
	Challenge string // Challenge to be used for signature.
}

// Tokens are associated with a public key, and are stored as a balance on the
// server. The model is a trust based private ledger, and generally tokens are
// used for anti-spam, to prevent a client from flooding the server with
// hundreds of messages and eating up all the storage space.
//
// When the a client wishes to consume some tokens, he signs a message
// specifying the amount of tokens to spend, the public key holding the tokens,
// and a challenge string (to prevent replay attacks).
type TokenTransaction struct {
	Challenge string // Challenge from the server.
	Amount    int64  // Amount to spend. Use -1 to indicate server decides.
	PubKey    string // Public key storing the tokens.
	Sig       string // Signature with private key holding the tokens.
}

func (t *TokenTransaction) SignableHash() []byte {
	h := sha256.New()
	h.Write([]byte(t.Challenge))
	h.Write([]byte(strconv.FormatInt(t.Amount, 10)))
	return h.Sum([]byte{})
}

// The RequestPaymentDetails RPC is used to get information on how to purchase
// tokens from the server.
// TODO(ortutay): Use BIP 70 instead.
type RequestPaymentDetailsArgs struct {
}

type RequestPaymentDetailsReply struct {
	Address BitcoinAddress // Address where server requests payment.
	Sig     string         // Signature by the server's private key.
}

// The BuyTokens RPC is used to purchase tokens from the server.
type BuyTokensArgs struct {
	RawTx  string // Raw bitcoin transaction that pays for the tokens.
	PubKey string // Public key where the sever sends tokens.
}

type BuyTokensReply struct {
}

// The ClaimTokens RPC is used to get tokens by signing a bitcoin address.
// Typically, a server will grant tokens if address has ever received bitcoins.
// Addresses can only be used to claim tokens once. This provides some level of
// anti-spam protection, since an spammer would, at least, be slowed by the
// conformation speed of the bitcoin network. The server may also implement
// checks for transaction fees on the addresses.
type ClaimTokensArgs struct {
	Challenge      string // Challenge from the server.
	PubKey         string // Public key where the sever sends tokens.
	BitcoinAddress string // Bitcoin address used to sign.
	Sig            string // Bitcoin signature of the challenge and public key.
}

func (a *ClaimTokensArgs) SignableHash() []byte {
	h := sha256.New()
	h.Write([]byte(a.Challenge))
	h.Write([]byte(a.PubKey))
	h.Write([]byte(a.BitcoinAddress))
	return h.Sum([]byte{})
}

type ClaimTokensReply struct {
}

// The GetBalance RPC is used by the client to check the number of tokens a
// public key holds.
type GetBalanceArgs struct {
	Challenge string // Challenge from the server.
	PubKey    string // Public key to get balance for.
	Sig       string // Signature of the args.
}

func (a *GetBalanceArgs) SignableHash() []byte {
	h := sha256.New()
	h.Write([]byte(a.Challenge))
	h.Write([]byte(a.PubKey))
	return h.Sum([]byte{})
}

type GetBalanceReply struct {
	Balance uint64
}

// The Burn RPC is used to spend tokens on nothing at all. Mainly used for
// testing.
type BurnArgs struct {
	Tokens TokenTransaction
}

type BurnReply struct {
}

// The StoreMessage RPC is used to store a message on the server. Typically,
// the server will charge some number of tokens to store messages.
type StoreMessageArgs struct {
	Tokens  TokenTransaction
	Message Message
}

type StoreMessageReply struct {
}

// The GetMessages RPC is used to get messages from the server that match some
// query.
// TODO(ortutay): We may want to add an optional tokens parameter to this as
// well.
type GetMessagesArgs struct {
	Query Query
}

type GetMessagesReply struct {
	Messages []Message
	Sig      string // TODO(ortutay): what is this for??
}

// Is the bitcoin address using a compressed public key?
func isCompressed(privKey *btcec.PrivateKey, addr string, netParams *btcnet.Params) (bool, error) {
	btcPubKey := (btcec.PublicKey)(privKey.PublicKey)
	serCompressed := btcPubKey.SerializeCompressed()
	compressedAddr, err := btcutil.NewAddressPubKey(serCompressed, netParams)
	if err != nil {
		return false, err
	}
	return compressedAddr.EncodeAddress() == addr, nil
}
