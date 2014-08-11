package bitnet

type BuyTokensArgs struct {
	RawTx  string // Bitcoin transaction that pays for the tokens.
	PubKey string // EC pub key where the sever sends tokens.
}

type BuyTokensReply struct {
}

type ChallengeArgs struct {
}

type ChallengeReply struct {
	Challenge string // Challenge to be used for signature.
}

type BurnArgs struct {
	TokensPubKey string // EC pub key corresponding to tokens to burn.
	Challenge    string // Challenge string being used for signature.
	Num          int64  // Number of tokens to burn.
	Sig          string // Sign with corresponding EC priv key.
}

type BurnReply struct {
}
