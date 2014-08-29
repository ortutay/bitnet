package bitnet

import (
	"bitbucket.org/ortutay/bitnet/util"
	"fmt"
	"github.com/conformal/btcec"
	"os"
	"strings"
	"testing"
)

func TestTokens(t *testing.T) {
	defer os.RemoveAll(util.InitTempAppDir(t))
	d := NewDatastore()
	_, pubKey := btcec.PrivKeyFromBytes(btcec.S256(), []byte("entropy"))
	want := uint64(100)
	if err := d.AddTokens(pubKey, int64(want)); err != nil {
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

func TestQuery(t *testing.T) {
	var m1 Message
	m1.Plaintext.AddHeader("from", "abcuser")
	m1.Plaintext.AddHeader("to", "xyzuser")
	m1.Plaintext.AddHeader("timestamp", "100")

	var m2 Message
	m2.Plaintext.AddHeader("from", "abcuser")
	m2.Plaintext.AddHeader("to", "otheruser")
	m2.Plaintext.AddHeader("timestamp", "200")

	var m3 Message
	m3.Plaintext.AddHeader("from", "abcuser")
	m3.Plaintext.AddHeader("to", "otheruser")
	m3.Plaintext.AddHeader("to", "onemoreuser")
	m3.Plaintext.AddHeader("timestamp", "300")

	var m4 Message
	m4.Plaintext.AddHeader("price", "10.51")

	var m5 Message
	m5.Plaintext.AddHeader("price", "11.134")

	defer os.RemoveAll(util.InitTempAppDir(t))
	d := NewDatastore()
	d.StoreMessage(&m1)
	d.StoreMessage(&m2)
	d.StoreMessage(&m3)
	d.StoreMessage(&m4)
	d.StoreMessage(&m5)

	m1Hash := m1.HashHex()

	var tests = []struct {
		desc  string
		query *Query
		want  []*Message
	}{
		{
			desc:  "string equals",
			query: &Query{Headers: map[string]string{"from =": "abcuser"}},
			want:  []*Message{&m1, &m2, &m3},
		},
		{
			desc:  "string equals (default op is equals)",
			query: &Query{Headers: map[string]string{"from": "abcuser"}},
			want:  []*Message{&m1, &m2, &m3},
		},
		{
			desc:  "string not equal (at least one match makes expression true)",
			query: &Query{Headers: map[string]string{"to !=": "otheruser"}},
			want:  []*Message{&m1, &m3},
		},
		{
			desc:  "numeric (integer) greater than",
			query: &Query{Headers: map[string]string{"timestamp >=": "200"}},
			want:  []*Message{&m2, &m3},
		},
		{
			desc:  "numeric (floating point) greater than",
			query: &Query{Headers: map[string]string{"timestamp <": "200.5"}},
			want:  []*Message{&m1, &m2},
		},
		{
			desc:  "numeric (floating point) equals",
			query: &Query{Headers: map[string]string{"price =": "11.134"}},
			want:  []*Message{&m5},
		},
		{
			desc:  "message-hash equals",
			query: &Query{Headers: map[string]string{"message-hash =": m1Hash}},
			want:  []*Message{&m1},
		},
	}

	for _, test := range tests {
		got, err := d.GetMessages(test.query)
		if err != nil {
			t.Errorf("%s\nGetMessages(%v)\nerror: %v", test.desc, test.query, err)
		}
		same := len(test.want) == len(got)
		if same {
			hashes := make(map[string]bool)
			for _, msg := range test.want {
				hashes[msg.HashHex()] = true
			}
			for _, msg := range got {
				if _, ok := hashes[msg.HashHex()]; !ok {
					same = false
					break
				}
			}
		}
		if !same {
			t.Errorf("%s\nGetMessage(%v)\nwant: %v\n got: %v", test.desc, test.query, joinMessages(test.want), joinMessages(got))
		}
	}
}

func joinMessages(msgs []*Message) string {
	var strs []string
	for _, msg := range msgs {
		strs = append(strs, fmt.Sprint(*msg))
	}
	return strings.Join(strs, ",")
}
