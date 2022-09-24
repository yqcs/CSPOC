package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func RsaEncoding(src, keyBytes string) []byte {
	// 读取内容到容器里面
	block, _ := pem.Decode([]byte(keyBytes))                // pem解码
	publicKey, errr := x509.ParsePKIXPublicKey(block.Bytes) // x509解码
	if errr != nil {
		return nil
	}
	// todo 使用公钥对明文进行加密
	retByte, errr := rsa.EncryptPKCS1v15(rand.Reader, publicKey.(*rsa.PublicKey), []byte(src))
	if errr != nil {
		return nil
	}
	return retByte
}
