package aes

/**
 * @Author nick
 * @Blog http://www.lampnick.com
 * @Email nick@lampnick.com
 */
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

type ecb struct {
	b         cipher.Block
	blockSize int
}
type ecbEncrypter ecb
type ecbDecrypter ecb

func newECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

// NewECBEncrypter returns a BlockMode which encrypts in electronic code book
// mode, using the given Block.
func NewECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(newECB(b))
}

// NewECBDecrypter returns a BlockMode which decrypts in electronic code book
// mode, using the given Block.
func NewECBDecrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbDecrypter)(newECB(b))
}

func Base64DecodeAndDecrypt(cipherText string, aesKey []byte) ([]byte, error) {
	decodeCipher, err := base64.StdEncoding.DecodeString(cipherText)
	if err != nil {
		return []byte{}, err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return []byte{}, err
	}
	blockMode := NewECBDecrypter(block)
	origData := make([]byte, len(decodeCipher))
	blockMode.CryptBlocks(origData, decodeCipher)
	origData = PKCS5UnPadding(origData)
	return origData, nil
}

func EncryptAndBase64(src []byte, key []byte) string {
	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("aesRandomKey error", err)
	}
	ecb := NewECBEncrypter(block)
	src = PKCS5Padding(src, block.BlockSize())
	crypt := make([]byte, len(src))
	ecb.CryptBlocks(crypt, src)
	return base64.StdEncoding.EncodeToString(crypt)
}

func PKCS5Padding(cipherText []byte, blockSize int) []byte {
	padding := blockSize - len(cipherText)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(cipherText, padText...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	// remove the last byte
	unPadding := int(origData[length-1])
	return origData[:(length - unPadding)]
}

func (x *ecbEncrypter) BlockSize() int {
	return x.blockSize
}
func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func (x *ecbDecrypter) BlockSize() int {
	return x.blockSize
}

func (x *ecbDecrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("crypto/cipher: input not full blocks")
	}
	if len(dst) < len(src) {
		panic("crypto/cipher: output smaller than input")
	}
	for len(src) > 0 {
		x.b.Decrypt(dst, src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}
