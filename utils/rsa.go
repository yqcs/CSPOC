package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
)

func RsaEncoding(src, keyBytes string) []byte {
	// 读取内容到容器里面
	block, _ := pem.Decode([]byte(keyBytes)) // pem解码
	if block == nil {
		return nil
	}
	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes) // x509解码
	if err != nil {
		return nil
	}
	retByte, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey.(*rsa.PublicKey), []byte(src))
	if err != nil {
		return nil
	}
	return retByte
}
