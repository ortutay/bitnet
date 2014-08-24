package bitnet

import (
	"bitbucket.org/ortutay/bitnet/util"
	"github.com/conformal/btcec"
	"os"
	"testing"
)

func TestTokens(t *testing.T) {
	defer os.RemoveAll(util.InitTempAppDir(t))
	d := NewDatastore()
	_, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), []byte("entropy"))
	want := uint64(100)
	if err := d.AddTokens(pubKey, want); err != nil {
		t.Fatal(err)
	}
	num, err := d.GetNumTokens(pubKey)
	if err != nil {
		t.Fatal(err)
	}
	if num != want {
		t.Errorf("want: %d, got: %d", want, num)
	}
}
