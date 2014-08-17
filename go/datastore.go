package bitnet

import (
	"encoding/hex"
	"github.com/peterbourgon/diskv"
	"math/big"
	"fmt"
	"sync"
	"github.com/conformal/btcec"
	"bitbucket.org/ortutay/bitnet/util"
)

const (
	tokensField = "tokens"
)

func stringForPubKey(pubKey *btcec.PublicKey) string {
	return hex.EncodeToString(pubKey.SerializeCompressed())
}

type Datastore struct {
	locks map[string]*sync.Mutex
}

func NewDatastore() *Datastore {
	var d Datastore
	d.locks = make(map[string]*sync.Mutex)
	return &d
}

func (d *Datastore) getDBForPubKey(pubKey *btcec.PublicKey) (*diskv.Diskv, *sync.Mutex) {
	pubKeyStr := stringForPubKey(pubKey)
	if _, ok := d.locks[pubKeyStr]; !ok {
		d.locks[pubKeyStr] = new(sync.Mutex)
	}
	lock := d.locks[pubKeyStr]
	path := fmt.Sprintf("%v/pubkey-%v.db", util.AppDir(), pubKeyStr)
	db := util.GetOrCreateDB(path)
	return db, lock
}

func (d *Datastore) AddTokens(pubKey *btcec.PublicKey, numTokens int64) error {
	fmt.Printf("AddTokens(%v, %v)\n", pubKey, numTokens)
	pubKeyStr := stringForPubKey(pubKey)
	db, lock := d.getDBForPubKey(pubKey)
	lock.Lock()
	defer lock.Unlock()
	dbValue := []byte("0")
	if db.Has(tokensField) {
		var err error
		dbValue, err = db.Read(tokensField)
		if err != nil {
			return fmt.Errorf("error reading from DB %v/%v: %v", pubKeyStr, tokensField, err)
		}
	}
	dbNumTokens := new(big.Int)
	if _, ok := dbNumTokens.SetString(string(dbValue), 10); !ok {
		return fmt.Errorf("error parsing %v/%v/%v", pubKeyStr, tokensField, dbValue)
	}
	dbNumTokens.Add(dbNumTokens, big.NewInt(numTokens))
	if err := db.Write(tokensField, []byte(dbNumTokens.String())); err != nil {
		return fmt.Errorf("error writing to DB %v/%v/%v: %v", pubKeyStr, tokensField, dbNumTokens.String(), err)
	}
	return nil
}
