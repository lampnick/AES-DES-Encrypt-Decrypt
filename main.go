package main

import (
	"encoding/json"
	"fmt"

	"github.com/lampnick/AES-DES-Encrypt-Decrypt/encrypt/helper"
)

/**
 * @Author nick
 * @Blog http://www.lampnick.com
 * @Email nick@lampnick.com
 */

var privateKey = []byte(`  
-----BEGIN RSA PRIVATE KEY-----
MIICWwIBAAKBgQCCuJ0KYjYfba1T64vLHP6Q7edika7uhkUhY27zMEQcJMvopOG+
clQbUJ/Wh2ws9xQtuSWSfANf1ssiMB90HEGt71oexDDAFGniVbsOBDO1ogHBnuU2
XxGJT0hf81T4oxcu6Fu93F4wr7R+obZqj99hR2QXYdARZHU+2zUlztqvIQIDAQAB
AoGAAx6cwM6vM/jOFh6c62/5s0O6LeQEJLUXmUBiOXOBbJqEMz0cFgtsbmpyJhB9
SGVtGdo9R02mVvctSdeUKJU0DAV0f/tFZJTdna/LA/HIy2A1gcGRtA+eAakvSZrC
J4FfmHlpXh9G6aiiGey5CEfsrsm1m6GfsiQJi2n7obEjXjECQQCHR7IwY9lAwrbU
GvQNXRREy6nf7TGPInv2j+/0TmJsA4Oz3h+tTD0JA4O4ITBOPUyGKvqQ/2JeDB1G
gtiP5EerAkEA919ygeXOO2VHbd5YCGUsAL/rYB8JLeBwV+kV9o2+4sN9NX+ojdY3
0UnEwx/dyFmd21j5lf/c5mFdPR5iueDoYwJAWBBlQDkPyae36xXsv/JS6oIGgP5g
38PcHOMQmuKYEaasCuBTkLXrmb2O9sOsNZKUCVdbLB8EQyLxv+AX6Hv75wJAIGaY
EPuQr6bsXC+rSC44PUDmC4kFIsUq8djNz6VxQzJnzAIUib9tQDRxWT1rRzq1um1F
A6invmUyWTcJp18WEQJAJRwDh34yCvPQDznFJSbC/COrmCD7Q2MT2yhmnLgKm5BB
f061X/GfHSG7Nc6S7kRipHVTQdTXUxrENvfgQb22vA==
-----END RSA PRIVATE KEY-----
`)
var publicKey = []byte(`
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCCuJ0KYjYfba1T64vLHP6Q7edi
ka7uhkUhY27zMEQcJMvopOG+clQbUJ/Wh2ws9xQtuSWSfANf1ssiMB90HEGt71oe
xDDAFGniVbsOBDO1ogHBnuU2XxGJT0hf81T4oxcu6Fu93F4wr7R+obZqj99hR2QX
YdARZHU+2zUlztqvIQIDAQAB
-----END PUBLIC KEY-----
`)

func main() {
	//original data
	data := map[string]interface{}{
		"name": "lampNick",
		"job":  "php",
	}
	//json serialized bytes data
	bytesData, err := json.Marshal(data)
	if err != nil {
		panic(err)
	}
	//encrypt
	encryptInfo, err := helper.Encrypt(string(bytesData), publicKey, privateKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("sourceData==>", data)
	fmt.Println("encryptInfo==>", encryptInfo)
	//decrypt
	decryptInfo, err := helper.Decrypt(encryptInfo, publicKey, privateKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("decryptInfo==>", decryptInfo)
}
