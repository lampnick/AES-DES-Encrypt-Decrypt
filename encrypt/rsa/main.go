package rsa

/**
 * @Author nick
 * @Blog http://www.lampnick.com
 * @Email nick@lampnick.com
 */

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

func parsePrivateKey(privateKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key decode error")
	}
	pkcs1PrivateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.New("private key parse error")
	}
	return pkcs1PrivateKey, nil
}

func parsePublicKey(publicKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pkixPublicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub, ok := pkixPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key type error")
	}
	return pub, nil
}

func PrivateKeySignAndBase64(privateKey []byte, data []byte) (string, error) {

	pkcs1PrivateKey, err := parsePrivateKey(privateKey)
	if err != nil {
		return "", err
	}
	h := sha1.New()
	h.Write(data)
	hashed := h.Sum(nil)

	signPKCS1v15, err := rsa.SignPKCS1v15(nil, pkcs1PrivateKey, crypto.SHA1, hashed)
	if err != nil {
		return "", err
	}
	base64EncodingData := base64.StdEncoding.EncodeToString(signPKCS1v15)
	return base64EncodingData, nil
}

func Base64DecodeAndPublicKeyVerifySign(publicKey []byte, data []byte, sign string) error {
	decodeSign, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return err
	}
	key, err := parsePublicKey(publicKey)
	if err != nil {
		return err
	}
	h := sha1.New()
	h.Write(data)
	hashed := h.Sum(nil)
	err = rsa.VerifyPKCS1v15(key, crypto.SHA1, hashed, decodeSign)
	if err != nil {
		return err
	}
	return nil
}

func PublicKeyEncryptAndBase64(src []byte, publicKey []byte) (string, error) {
	key, err := parsePublicKey(publicKey)
	if err != nil {
		return "", err
	}
	encryptPKCS1v15, err := rsa.EncryptPKCS1v15(rand.Reader, key, src)
	if err != nil {
		return "", err
	}
	base64EncodingData := base64.StdEncoding.EncodeToString(encryptPKCS1v15)
	return base64EncodingData, nil
}

func Base64DecodeAndPrivateKeyDecrypt(cipherText string, privateKey []byte) ([]byte, error) {
	decodeCipher, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return []byte{}, err
	}
	pkcs1PrivateKey, err := parsePrivateKey(privateKey)
	if err != nil {
		return []byte{}, err
	}
	decrypt, err := rsa.DecryptPKCS1v15(rand.Reader, pkcs1PrivateKey, decodeCipher)
	if err != nil {
		return []byte{}, err
	}
	return decrypt, nil
}
