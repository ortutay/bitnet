package bitnet

// Data structures
type BitcoinAddress string

type Section struct {
	// Expected headers:
	// - "datetime": ISO 8601 date/time
	// - "sender-public-key": Public key of the sender.
	// - "sender-sig": Signature of sender corresponding to "sender-public-key".
	//    The server will validate the signature.
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
	RawTx string // Raw bitcoin transaction that pays for the tokens, hex encoded.
	Pub   string // EC pub key where the sever sends tokens.
}

type BuyTokensReply struct {
}

type ChallengeArgs struct {
}

type ChallengeReply struct {
	Challenge string // Challenge to be used for signature.
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
