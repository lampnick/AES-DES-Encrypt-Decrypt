# TODO
Test case.

# 使用说明
参考main.go构建需要加密的数据，传入公私钥即可加解密。

# 签名算法介绍
为了保证数据的传输安全，在调用API时使用到了AES（ECB SHA128 PKCS5Padding）和RSA两种通用的加密算法。

# 名词解释
- merchantNo:平台方分配给第三方的账户编号
- aesRandomKey：随机生成长度为16位的字符串(由字母和数字组成)作为AES随机密钥
- merchantPrivateKey：第三方私钥，第三方采用RSA算法生成。
- merchantPublicKey：第三方公钥，第三方采用RSA算法生成。需要提供给平台方。
- platformPublicKey：平台方公钥，平台方提供给第三方。
- encryptData：使用AES算法加密后的密文
- encryptAesKey：使用RSA算法加密后的密钥
- verifyData：encryptAesKey拼接上encryptData
- sign：对verifyData进行签名后的数据

# 加密数据步骤详解（使用GO代码说明）
- 假设需要加密的数据参数列表如下：
```
data := map[string]interface{}{
		"name": "lampNick",
		"job":  "php",
	}
```
- 随机生成长度为16位的字符串(由字母和数字组成)作为AES随机密钥aesRandomKey
```
aesRandomKey := helper.GetRandomString(16)
```
- 使用AES算法通过aesRandomKey加密json序列化后的数据，然后进行base64编码得到encryptData
```
    bytes, err := json.Marshal(data)
	if err != nil {
		panic("json encode error")
	}
    encryptData := aes.AesEncryptAndBase64(bytes, []byte(aesRandomKey))
```
- 使用RSA算法通过platformPublicKey对随机生成的AES密钥(aesRandomKey)进行加密并用base64进行编码得到encryptAesKey
```
    encryptAesKey, err := rsa.PublicKeyEncryptAndBase64([]byte(aesRandomKey), platformPublicKey)
```
- 将AES加密密钥拼接上加密密文得到待签名数据，使用merchantPrivateKey对待签名数据,生成基于SHA1的RSA数字签名，签名后进行base64编码得到sign
```
    verifyData := encryptAesKey + encryptData
    sign, _ := rsa.PrivateKeySignAndBase64(privateKey, []byte(verifyData))
```
- 返回verifyData、encryptAesKey、sign


- 向API接口发生HTTP请求,请求的参数包括 encryptData、encryptKey、sign、merchantNo


# 解密数据步骤详解（使用GO代码说明）

- 假设获取到的加密数据如下：
```
    encryptData: PI0BQOV6XeOCRKF22yP3KewfUHluwy+/9e0k7PpUCpNzl9/LpICGkX8rimWq2O9BDW6aY47eEotknEdX0lsLWnH0QXc6WcIZDIGeLVZZTpNDzASz/E4n/YawV4YpiKE/cNiivEd00EvBP1mRg9g4C6XNRnUrMYsOavLU86gmqeMODQdumeJaN3UNlYn4ovSLbhy8SNUbAD0Z2g7DeUA3MwDwaRJ6u/Wd7lE+zqQ7zSqmBs1HuixpxSJKR3e+w5GWPh/xevJHbwBL2CBCmxv+rAKgBai+JTnKgtdX8xAZo/Ukgtri4/VkcmtSvE8gyazOrjxb4GmgYWwOHVizE/rau8bkzua+Xms1M2a/CqoSppM5S2gFKhvxq1ATxfnqyeB6/tB11Gx3Viy64AWXPtPmkpyTdrv46fA3JXFKwQQrwMM+fa6zr+LH8xoW8qV7wK4somF1WRDZo3nmAKp7m8HqmcSH5f0dohpVeUkjUdcpsLUUEqhNC8ENQUOaSY/JR4blz4aXOIfUBsz5ygPodHenQA==
    encryptAesKey: 14XOz1o1zWCGRDrPM/xbdVilQLMLvecmZD2vwC9OCStt4ywyjirERXDZ0BEltmum1S9AS2r19Jzl5RVTlrrRO3GaxQ02BWDNj5FfGMLSWUIkYB23a83Ur07ZAcKEm3gInitEOsoeN+8h+unX/bRKohn1jNIsBE3+GNvQs4I5mwA=
    sign: amj+0Jl/mRcPUm5Bn/uwm/QFo0yAqsxPPMUnvjzt8r3H9Adq7qqF19wEkQ77lvfZRpS8zcFSkDZisnPyiSLmQqOj/gjNojHm8VcY61YKNA28XI/iqYUVAGOuKOU70D3tuHJmsxmRZ0bAMLqH5JA6SSAT6lal0LhrCX/Rv9EL+I0=

```
- 获取接收到的密文encryptData、加密后的密钥encryptAesKey、签名sign
- 验证签名，将encryptAesKey拼接上encryptData得到verifyData，将得到的sign进行base64解码，然后使用platformPublicKey对verifyData进行RSA验证签名验证，签名验证通过
```
    verifyData := encryptAesKey + encryptData
    verifySign := rsa.Base64DecodeAndPublicKeyVerifySign(platformPublicKey, []byte(verifyData), sign)
	if verifySign != nil {
		panic("verify sign error")
	} else {
		fmt.Println("verify sign correct")
	}
```

- 解密encryptAesKey，先进行base64解码，然后使用RSA算法通过merchantPrivateKey进行解密
```
    decryptAesKey, err := rsa.Base64DecodeAndPrivateKeyDecrypt(encryptAesKey, privateKey)
	if err != nil {
		panic(err)
	}
```
- 解密encryptData，先进行base64解码，然后使用AES算法通过上一步解密出来的密钥进行解密,最后进行json反序列化
```
    aesDecrypt, err := aes.Base64DecodeAndAesDecrypt(encryptData, decryptAesKey)
	if err != nil {
		panic(err)
	}
	fmt.Println("aesDecrypt:", aesDecrypt)

	var aesDecryptMap map[string]interface{}
	json.Unmarshal(aesDecrypt, &aesDecryptMap)
	fmt.Println("aesDecryptMap:", aesDecryptMap)
```
