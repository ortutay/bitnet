package bitnet

type TokenTransaction struct {
	Challenge string // Challenge from the server.
	Amount    int64  // Amount to spend.
	Sig       string // Signature with private key holding the tokens.
}

type BuyTokensArgs struct {
	RawTx string // Bitcoin transaction that pays for the tokens.
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
	Transaction TokenTransaction
}

type BurnReply struct {
}
