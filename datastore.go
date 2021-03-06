package bitnet

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/conformal/btcec"
	log "github.com/golang/glog"
	"github.com/ortutay/bitnet/util"
	"github.com/peterbourgon/diskv"
	"math"
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
	messagesDBRelativePath      = "messages.db"

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
	pubKeyStr := stringForPubKey(pubKey)
	db, lock := d.getDBForPubKey(pubKey)
	lock.Lock()
	defer lock.Unlock()
	dbNumTokens, err := d.getNumTokensFromDB(db, pubKey)
	if err != nil {
		return err
	}
	if uint64(numTokens) < 0 && uint64(-numTokens) > dbNumTokens {
		return errors.New("insufficient balance")
	}
	oldDBNumTokens := dbNumTokens
	if numTokens >= 0 {
		dbNumTokens += uint64(numTokens)
	} else {
		dbNumTokens -= uint64(-numTokens)
	}

	// Handle potential wrap-around from overlow.
	if numTokens > 0 && dbNumTokens < oldDBNumTokens {
		dbNumTokens = math.MaxUint64
	}

	ser := strconv.FormatUint(dbNumTokens, 10)
	if err := db.Write(tokensField, []byte(ser)); err != nil {
		return fmt.Errorf("error writing to DB %v/%v/%v: %v", pubKeyStr, tokensField, ser, err)
	}
	return nil
}

func (d *Datastore) GetNumTokens(pubKey *btcec.PublicKey) (uint64, error) {
	db, lock := d.getDBForPubKey(pubKey)
	lock.Lock()
	defer lock.Unlock()
	return d.getNumTokensFromDB(db, pubKey)
}

func (d *Datastore) getNumTokensFromDB(db *diskv.Diskv, pubKey *btcec.PublicKey) (uint64, error) {
	dbValue := []byte("0")
	if db.Has(tokensField) {
		var err error
		dbValue, err = db.Read(tokensField)
		if err != nil {
			return 0, fmt.Errorf("error reading from DB %v/%v: %v", tokensField, err)
		}
	}
	dbNumTokens, err := strconv.ParseUint(string(dbValue), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("error parsing %v/%v/%v", pubKey, tokensField, dbValue)
	}
	return dbNumTokens, nil
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

func (d *Datastore) HasUsedAddress(btcAddress *BitcoinAddress) bool {
	db, lock := d.getDBForRelativePath(usedAddressesDBRelativePath)
	lock.Lock()
	defer lock.Unlock()
	return db.Has(btcAddress.String())
}

func (d *Datastore) StoreMessage(msg *Message) error {
	db, lock := d.getDBForRelativePath(messagesDBRelativePath)
	lock.Lock()
	defer lock.Unlock()

	hashHex := hex.EncodeToString(msg.SignableHash())
	if db.Has(hashHex) {
		return nil
	}
	// TODO(ortutay): Use JSON for easy inspection. Switch to another format later
	// if there are efficiency concerns.
	msgJSON, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("couldn't marshal %v to JSON: %v", msg, err)
	}
	if err := db.Write(hashHex, []byte(msgJSON)); err != nil {
		return err
	}
	return nil
}

func (d *Datastore) GetMessages(query *Query) ([]*Message, error) {
	// TODO(ortutay): For now, we just iterate over all messages and execut the
	// query. This is inefficeint, and we will want to rethink how this works in
	// the future. We will probably want to use a more efficient datastore, and we
	// may also want to restrict query complexity.
	db, lock := d.getDBForRelativePath(messagesDBRelativePath)
	lock.Lock()
	defer lock.Unlock()

	var msgs []*Message
	for key := range db.Keys() {
		msgJSON, err := db.Read(key)
		if err != nil {
			return nil, fmt.Errorf("error reading message %s from datastore: %v", key, err)
		}
		var msg Message
		if err := json.Unmarshal(msgJSON, &msg); err != nil {
			// TODO(ortutay): We may want to continue processing other items, but for
			// now, just return error.
			return nil, fmt.Errorf("couldn't unmarshal %v from JSON: %v", string(msgJSON), err)
		}
		if !query.Matches(&msg) {
			continue
		}
		msgs = append(msgs, &msg)
	}

	return msgs, nil
}
