package helper

/**
 * @Author nick
 * @Blog http://www.lampnick.com
 * @Email nick@lampnick.com
 */
import (
	"AES-DES-Encrypt-Decrypt/encrypt/aes"
	"AES-DES-Encrypt-Decrypt/encrypt/rsa"
	"errors"
	"math/rand"
	"time"
)

type EncryptInfo struct {
	EncryptData string
	EncryptKey  string
	Sign        string
}

type DecryptInfo struct {
	Data string
}

func GetRandomString(l int) string {
	str := "0123456789ABCDEFGHIGKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	byteStr := []byte(str)
	var result []byte
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result = append(result, byteStr[r.Intn(len(byteStr))])
	}
	return string(result)
}

func Encrypt(data string, publicKey, privateKey []byte) (*EncryptInfo, error) {
	encryptInfo := new(EncryptInfo)
	aesRandomKey := GetRandomString(16)
	encryptData := aes.EncryptAndBase64([]byte(data), []byte(aesRandomKey))
	encryptAesKey, err := rsa.PublicKeyEncryptAndBase64([]byte(aesRandomKey), publicKey)
	if err != nil {
		return encryptInfo, err
	}
	sortedValue := encryptAesKey + encryptData
	sign, _ := rsa.PrivateKeySignAndBase64(privateKey, []byte(sortedValue))
	encryptInfo.EncryptData = encryptData
	encryptInfo.EncryptKey = encryptAesKey
	encryptInfo.Sign = sign
	return encryptInfo, nil
}

func Decrypt(encrypt *EncryptInfo, publicKey, privateKey []byte) (*DecryptInfo, error) {
	decryptInfo := new(DecryptInfo)
	verifyData := encrypt.EncryptKey + encrypt.EncryptData
	verifySign := rsa.Base64DecodeAndPublicKeyVerifySign(publicKey, []byte(verifyData), encrypt.Sign)
	if verifySign != nil {
		return decryptInfo, errors.New("verify sign failed")
	}
	decryptAesKey, err := rsa.Base64DecodeAndPrivateKeyDecrypt(encrypt.EncryptKey, privateKey)
	if err != nil {
		return decryptInfo, err
	}
	aesDecrypt, err := aes.Base64DecodeAndDecrypt(encrypt.EncryptData, decryptAesKey)
	if err != nil {
		return decryptInfo, err
	}

	decryptInfo.Data = string(aesDecrypt)
	return decryptInfo, nil
}
