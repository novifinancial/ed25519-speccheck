// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the APACHE 2.0 license found in
// the LICENSE file in the root directory of this source tree.

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ed25519"
	"io/ioutil"
	"log"
)

type Case struct {
	Message   string
	Pub_Key   string
	Signature string
}

func main() {
	content, err := ioutil.ReadFile("cases.json")
	if err != nil {
	   log.Fatal(err)
	}
	caseString := string(content)

	var cases []Case

	json.Unmarshal([]byte(caseString), &cases)
	//fmt.Printf("Cases : %+v", cases)

	fmt.Printf("\n|Go             |")
	for i, c := range cases {
		pk_bytes, _ := hex.DecodeString(c.Pub_Key)
		m_bytes, _ := hex.DecodeString(c.Message)
		sig_bytes, _ := hex.DecodeString(c.Signature)

		pk := ed25519.PublicKey(pk_bytes)

		ver := ed25519.Verify(pk, m_bytes, sig_bytes)

		if ver {
				fmt.Printf(" V |")
		} else {
				fmt.Printf(" X |")
		}
		_ = i
	}
	fmt.Printf("\n")

}
