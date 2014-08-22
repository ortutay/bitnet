package bitnet

import (
	"bitbucket.org/ortutay/bitnet/util"
	"encoding/hex"
	"fmt"
	"github.com/conformal/btcec"
	log "github.com/golang/glog"
	"github.com/peterbourgon/diskv"
	"math/big"
	"strconv"
	"sync"
	"time"
)

const (
	// pubkey datastores
	tokensField = "tokens"

	datastoreRelativePath = "datastore"

	challengeDBRelativePath     = "challenges.db"
	usedAddressesDBRelativePath = "usedAddresses.db"

	challengeExpiresSeconds = 3600 * 24 // 24 hours
)

func datastorePath() string {
	return fmt.Sprintf("%v/%v", util.AppDir(), datastoreRelativePath)
}

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
	relPath := fmt.Sprintf("pubkey-%s.db", stringForPubKey(pubKey))
	return d.getDBForRelativePath(relPath)
}

func (d *Datastore) getDBForRelativePath(relPath string) (*diskv.Diskv, *sync.Mutex) {
	path := fmt.Sprintf("%s/%s", datastorePath(), relPath)
	if _, ok := d.locks[path]; !ok {
		d.locks[path] = new(sync.Mutex)
	}
	lock := d.locks[path]
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
			return fmt.Errorf("error reading from DB %v/%v: %v", tokensField, err)
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

func (d *Datastore) StoreChallenge(challengeStr string) error {
	db, lock := d.getDBForRelativePath(challengeDBRelativePath)
	lock.Lock()
	defer lock.Unlock()

	expires := strconv.FormatInt(time.Now().Unix()+challengeExpiresSeconds, 10)
	log.Infof("Adding new challenge %q, expires %q", challengeStr, expires)
	if err := db.Write(challengeStr, []byte(expires)); err != nil {
		log.Errorf("Error writing challenge %q: %v", challengeStr, err)
		return err
	}

	return nil
}

func (d *Datastore) GetChallengeExpiration(challengeStr string) (int64, error) {
	db, lock := d.getDBForRelativePath(challengeDBRelativePath)
	lock.Lock()
	defer lock.Unlock()

	if !db.Has(challengeStr) {
		return 0, nil
	}

	data, err := db.Read(challengeStr)
	if err != nil {
		log.Errorf("Error reading challenge %q: %v", challengeStr, err)
		return 0, err
	}
	expires, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		log.Errorf("Error parsing challenge expiration %q: %v", data, err)
		return 0, fmt.Errorf("couldn't parse %q: %v", data, err)
	}
	return expires, nil
}

func (d *Datastore) HasChallenge(challengeStr string) bool {
	db, lock := d.getDBForRelativePath(challengeDBRelativePath)
	lock.Lock()
	defer lock.Unlock()
	return db.Has(challengeStr)
}

func (d *Datastore) DeleteChallenge(challengeStr string) error {
	db, lock := d.getDBForRelativePath(challengeDBRelativePath)
	lock.Lock()
	defer lock.Unlock()

	if err := db.Erase(challengeStr); err != nil {
		log.Errorf("Error erasing challenge %q: %v", challengeStr, err)
		return err
	}

	return nil
}

func (d *Datastore) StoreUsedAddress(btcAddress *BitcoinAddress) error {
	db, lock := d.getDBForRelativePath(usedAddressesDBRelativePath)
	lock.Lock()
	defer lock.Unlock()

	if db.Has(btcAddress.String()) {
		return nil
	}
	if err := db.Write(btcAddress.String(), []byte("")); err != nil {
		return err
	}

	return nil
}
