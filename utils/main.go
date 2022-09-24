package utils

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/ck00004/CobaltStrikeParser-Go/lib/http"
)

var TYPE_SHORT = 1
var TYPE_INT = 2
var TypeStr = 3

var SupportedVersions = []int{3, 4}

var u = flag.String("u", "", "This can be a url (if started with http/s)")
var f = flag.String("f", "", "This can be a file path (if started with http/s)")
var o = flag.String("o", "", "out file")
var t = flag.Int("t", 30, "timeouts. default:20")
var br = flag.Int("br", 1, "thread,import file valid. default:1")

func GetPublicKey(s string) string {
	if *f != "" {
		var wg sync.WaitGroup
		var ChanUrlList chan string
		var num = 0
		var mutex sync.Mutex
		var urllist []string
		filepath := *f
		file, err := os.OpenFile(filepath, os.O_RDWR, 0666)
		if err != nil {
			fmt.Println("Open file error!", err)
			return ""
		}
		defer file.Close()

		buf := bufio.NewReader(file)
		for {
			line, err := buf.ReadString('\n')
			line = strings.TrimSpace(line)
			if line != "" {
				urllist = append(urllist, line)
			}
			if err != nil {
				if err == io.EOF {
					break
				} else {
					return ""
				}
			}
		}
		ChanUrlList = make(chan string, len(urllist))
		for filelen := 0; filelen < len(urllist); filelen++ {
			ChanUrlList <- urllist[filelen]
		}
		for i := 0; i < *br; i++ {
			wg.Add(1)
			go BeaconInitThread(&wg, &num, &mutex, ChanUrlList, *o)
		}

		close(ChanUrlList)
		wg.Wait()
	} else {
		return beaconinit(s)
	}
	return ""
}

func BeaconInitThread(wg *sync.WaitGroup, num *int, mutex *sync.Mutex, ChanUrlList chan string, filename string) {
	defer wg.Done()
	for one := range ChanUrlList {
		go incrNum(num, mutex)
		host := one
		beaconinit(host)
	}
}

func incrNum(num *int, mutex *sync.Mutex) {
	mutex.Lock()
	*num = *num + 1
	mutex.Unlock()
}

func beaconinit(host string) string {
	var resp_x64 *http.Response
	var err_x64 error
	var resp *http.Response
	var err error
	var stager *http.Response
	var stager_err error
	var stager64 *http.Response
	var stager_err_x64 error
	var is_x86 bool = true
	var is_x64 bool = true
	var is_stager_x86 bool = true
	var is_stager_x64 bool = true
	var buf []byte
	var tr *http.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	var client *http.Client = &http.Client{
		Timeout:   time.Duration(*t) * time.Second,
		Transport: tr,
	}
	var host_x86 string = host + "/" + MSFURI()
	var host_x64 string = host + "/" + MSFURI_X64()
	var stager_x86 string = host + "/" + "stager"
	var stager_x64 string = host + "/" + "stager64"
	resp, err = client.Get(host_x86)
	resp_x64, err_x64 = client.Get(host_x64)
	stager, stager_err = client.Get1(stager_x86, 1)
	stager64, stager_err_x64 = client.Get1(stager_x64, 1)

	if err != nil || resp.StatusCode != 200 {
		is_x86 = false
		//if filename == "" {
		//	fmt.Println("error:", err, "beacon stager x86 not found")
		//} else {
		//	fmt.Println("error:", err, "beacon stager x86 not found")
		//	bodyMap["URL"] = host
		//	if err != nil {
		//		bodyMap["error"] = err.Error() + "beacon stager x86 not found"
		//	} else {
		//		bodyMap["error"] = "beacon stager x86 not found"
		//	}
		//	var bodyerror string = MapToJson(bodyMap)
		//	JsonFileWrite(filename, bodyerror)
		//}
	}
	if err_x64 != nil || resp_x64.StatusCode != 200 {
		is_x64 = false
		//if filename == "" {
		//	fmt.Println("error:", err_x64, "beacon stager x64 not found")
		//} else {
		//	fmt.Println("error", err_x64, "beacon stager x64 not found")
		//	bodyMap["URL"] = host
		//	if err_x64 != nil {
		//		bodyMap["error"] = err_x64.Error() + "beacon stager x64 not found"
		//	} else {
		//		bodyMap["error"] = "beacon stager x64 not found"
		//	}
		//	var bodyerror string = MapToJson(bodyMap)
		//	JsonFileWrite(filename, bodyerror)
		//}
	}
	if stager_err != nil || stager.StatusCode != 200 {
		is_stager_x64 = false
		//if filename == "" {
		//	fmt.Println("error:", stager_err, "beacon stager x64 not found")
		//} else {
		//	fmt.Println("error", stager_err, "beacon stager x64 not found")
		//	bodyMap["URL"] = host
		//	if stager_err != nil {
		//		bodyMap["error"] = stager_err.Error() + "beacon stager x64 not found"
		//	} else {
		//		bodyMap["error"] = "beacon stager x64 not found"
		//	}
		//	var bodyerror string = MapToJson(bodyMap)
		//	JsonFileWrite(filename, bodyerror)
		//}
	}
	if stager_err_x64 != nil || stager64.StatusCode != 200 {
		is_stager_x64 = false
		//if filename == "" {
		//	fmt.Println("error:", stager_err_x64, "beacon stager x64 not found")
		//} else {
		//	fmt.Println("error", stager_err_x64, "beacon stager x64 not found")
		//	bodyMap["URL"] = host
		//	if stager_err_x64 != nil {
		//		bodyMap["error"] = stager_err_x64.Error() + "beacon stager x64 not found"
		//	} else {
		//		bodyMap["error"] = "beacon stager x64 not found"
		//	}
		//	var bodyerror string = MapToJson(bodyMap)
		//	JsonFileWrite(filename, bodyerror)
		//}
	}
	var body []byte
	if is_x86 != false {
		defer resp.Body.Close()
		body, _ = io.ReadAll(resp.Body)
	}
	if is_x64 != false {
		defer resp_x64.Body.Close()
		body, _ = io.ReadAll(resp_x64.Body)
	}
	if is_stager_x86 != false {
		defer stager.Body.Close()
		body, _ = io.ReadAll(stager.Body)
	}
	if is_stager_x64 != false {
		defer stager64.Body.Close()
		body, _ = io.ReadAll(stager64.Body)
	}
	if is_x64 == false && is_x86 == false && is_stager_x86 == false && is_stager_x64 == false {
		fmt.Println(host + " is not checksum8 and stager")
		return ""
	}
	if bytes.Index(body, []byte("EICAR-STANDARD-ANTIVIRUS-TEST-FILE")) == -1 {
		buf = decrypt_beacon(body)
	} else {
		fmt.Println("trial version")
		os.Exit(0)
	}
	return base64.StdEncoding.EncodeToString([]byte(beacon_config(buf)["PublicKey"]))
}

func beacon_config(buf []byte) map[string]string {
	for _, value := range SupportedVersions {
		if value == 3 {
			var offset int
			var offset1 int
			var offset2 int
			offset = bytes.Index(buf, []byte("\x69\x68\x69\x68\x69\x6b")) //3的兼容
			if offset != -1 {
				offset1 = bytes.Index(buf[offset:bytes.Count(buf, nil)-1], []byte("\x69\x6b\x69\x68\x69\x6b"))
				if offset1 != -1 {
					offset2 = bytes.Index(buf[offset : bytes.Count(buf, nil)-1][offset1:bytes.Count(buf[offset:bytes.Count(buf, nil)-1], nil)-1], []byte("\x69\x6a"))
					if offset2 != -1 {
						return BeaconSettings(decode_config(buf[offset:bytes.Count(buf, nil)-1], value))
					}
				}
			}
		} else if value == 4 {
			var offset int
			var offset1 int
			var offset2 int
			offset = bytes.Index(buf, []byte("\x2e\x2f\x2e\x2f\x2e\x2c")) //4的兼容
			if offset != -1 {
				offset1 = bytes.Index(buf[offset:bytes.Count(buf, nil)-1], []byte("\x2e\x2c\x2e\x2f\x2e\x2c"))
				if offset1 != -1 {
					offset2 = bytes.Index(buf[offset : bytes.Count(buf, nil)-1][offset1:bytes.Count(buf[offset:bytes.Count(buf, nil)-1], nil)-1], []byte("\x2e"))
					if offset2 != -1 {
						return BeaconSettings(decode_config(buf[offset:bytes.Count(buf, nil)-1], value))
					}
				}
			}
		}
	}
	return map[string]string{"error": "beacon config error"}
}

func JsonFileWrite(filename string, bodyText string) {
	var f *os.File
	var err1 error
	if checkFileIsExist(filename) { //如果文件存在
		f, err1 = os.OpenFile(filename, os.O_APPEND|os.O_WRONLY, 0666) //打开文件
		if err1 != nil {
			panic(err1)
		}
	} else {
		f, err1 = os.Create(filename) //创建文件
		if err1 != nil {
			panic(err1)
		}
	}
	defer f.Close()
	_, err1 = f.WriteString(bodyText)
	if err1 != nil {
		panic(err1)
	}
}

func checkFileIsExist(filename string) bool {
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return false
	}
	return true
}

func checksum8(uri string, n int) bool {
	var sum8 int
	if len(uri) < 4 {
		return false
	} else {
		for i := 0; i < len(uri); i++ {
			sum8 += int(uri[i])
		}
		if (sum8 % 256) == n {
			return true
		}
	}
	return false
}

func MSFURI() string {
	var uri string
	var az19 = "abcdefhijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567899"
	for {
		uri = string(az19[rand.Intn(len(az19))]) + string(az19[rand.Intn(len(az19))]) + string(az19[rand.Intn(len(az19))]) + string(az19[rand.Intn(len(az19))])
		if checksum8(uri, 92) {
			break
		}
	}
	return uri
}

func MSFURI_X64() string {
	var uri string
	var az19 string = "abcdefhijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567899"
	for {
		uri = string(az19[rand.Intn(len(az19))]) + string(az19[rand.Intn(len(az19))]) + string(az19[rand.Intn(len(az19))]) + string(az19[rand.Intn(len(az19))])
		if checksum8(uri, 93) {
			break
		}
	}
	return uri
}

// 转换函数
func IntToBytes(n int, b int) []byte {
	switch b {
	case 1:
		var tmp int8 = int8(n)
		var bytesBuffer *bytes.Buffer = bytes.NewBuffer([]byte{})
		binary.Write(bytesBuffer, binary.BigEndian, &tmp)
		return bytesBuffer.Bytes()
	case 2:
		var tmp int16 = int16(n)
		var bytesBuffer *bytes.Buffer = bytes.NewBuffer([]byte{})
		binary.Write(bytesBuffer, binary.BigEndian, &tmp)
		return bytesBuffer.Bytes()
	case 3, 4:
		var tmp int32 = int32(n)
		var bytesBuffer *bytes.Buffer = bytes.NewBuffer([]byte{})
		binary.Write(bytesBuffer, binary.BigEndian, &tmp)
		return bytesBuffer.Bytes()
	}
	return nil
}

type packedSetting_init_type struct {
	pos                   int
	datatype              int
	length                int
	isBlob                bool
	isHeaders             bool
	isIpAddress           bool
	isBool                bool
	isDate                bool
	isMalleableStream     bool
	boolFalseValue        int
	isProcInjectTransform bool
	hashBlob              bool
	enum                  map[byte]string
	mask                  map[byte]string
	transform_get         string
	transform_post        string
}

type packedsettingInitTypeoptions func(*packedSetting_init_type)

func WriteisBlob(isBlob bool) packedsettingInitTypeoptions {
	return func(p *packedSetting_init_type) {
		p.isBlob = isBlob
	}
}

func DefaultpackedSetting_init_type(p *packedSetting_init_type) *packedSetting_init_type {
	p.isBlob = false
	p.isHeaders = false
	p.isIpAddress = false
	p.isBool = false
	p.isDate = false
	p.isMalleableStream = false
	p.boolFalseValue = 0
	p.isProcInjectTransform = false
	p.hashBlob = false
	p.enum = make(map[byte]string)
	p.mask = make(map[byte]string)
	p.transform_get = ""
	p.transform_post = ""
	return p
}

func packedSettinginit(pos, datatype, length int, options ...packedsettingInitTypeoptions) *packedSetting_init_type {
	var p = &packedSetting_init_type{
		pos:      pos,
		datatype: datatype,
		length:   length,
	}
	p = DefaultpackedSetting_init_type(p)
	var op packedsettingInitTypeoptions
	for _, op = range options {
		// 遍历调用函数，进行数据修改
		op(p)
	}
	if datatype == TypeStr && length == 0 { //这里没处理TYPE_STR
		fmt.Println("if datatype is TYPE_STR then length must not be 0")
		os.Exit(1)
	}
	if datatype == TYPE_SHORT {
		p.length = 2
	} else if datatype == TYPE_INT {
		p.length = 4
	}
	return p
}

func binaryRepr(p *packedSetting_init_type) []byte {
	var selfRepr = make([]byte, 6)
	selfRepr = append(selfRepr[:1], IntToBytes(p.pos, 1)...)
	selfRepr = append(selfRepr[:3], IntToBytes(p.datatype, 1)...)
	selfRepr = append(selfRepr[:4], IntToBytes(p.length, 2)...)
	return selfRepr
}

func BeaconSettings(fullConfigData []byte) map[string]string {

	var BeaconConfig = make(map[string]string)
	xa := prettyRepr(fullConfigData, packedSettinginit(7, 3, 256, WriteisBlob(true)))
	BeaconConfig["PublicKey"] = xa
	return BeaconConfig
}

// InetNtoA 方法，接受4个值，给s赋值
func InetNtoA(ip []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3])
}

func prettyRepr(data []byte, p *packedSetting_init_type) string {
	var dataOffset = bytes.Index(data, binaryRepr(p))
	if dataOffset < 0 && p.datatype == TypeStr { //这里用的是confConsts.TYPE_STR
		p.length = 16
		for {
			if p.length < 2048 {
				p.length = p.length * 2
				dataOffset = bytes.Index(data, binaryRepr(p))
			}
			if dataOffset > 0 {
				break
			}
			if p.length >= 2048 {
				break
			}
		}
	}
	if dataOffset < 0 {
		return "Not Found"
	}
	var repr_len = len(binaryRepr(p))
	var conf_data = data[dataOffset+repr_len : dataOffset+repr_len+p.length]
	if p.datatype == TYPE_SHORT { //confConsts.TYPE_SHORT:
		var conf_data = binary.BigEndian.Uint16(conf_data)
		if p.isBool {
			if conf_data == uint16(p.boolFalseValue) {
				var ret = "false"
				return ret
			} else {
				var ret = "true"
				return ret
			}
		} else if len(p.enum) > 0 {
			return p.enum[byte(conf_data)]
		} else if len(p.mask) > 0 {
			var ret_arr string
			var v string
			var k byte
			for k, v = range p.mask {
				if k == 0 && k == byte(conf_data) {
					ret_arr = ret_arr + " " + v
				}
				if (k & byte(conf_data)) != 0 {
					ret_arr = ret_arr + " " + v
				}
			}
			return ret_arr
		} else {
			return fmt.Sprint(conf_data)
		}
	} else if p.datatype == TYPE_INT { // confConsts.TYPE_INT
		if p.isIpAddress {
			return InetNtoA(conf_data)
		} else {
			var conf_data uint32 = binary.BigEndian.Uint32(conf_data)
			if p.isDate && (conf_data != 0) {
				var year string = fmt.Sprint(conf_data)[0:4]
				var mouth string = fmt.Sprint(conf_data)[4:6]
				var day = fmt.Sprint(conf_data)[6:]
				return fmt.Sprintf("%v-%v-%v", year, mouth, day)
			}
			return fmt.Sprint(conf_data)
		}
	}
	if p.isBlob {
		if len(p.enum) > 0 {
			var i int = 0
			var ret_arr string
			for {
				if i > len(conf_data) {
					break
				}
				var v byte = conf_data[i]
				if v == 0 {
					return ret_arr
				}
				var ret_arr_tmp string = p.enum[v]
				if ret_arr_tmp != "None" {
					ret_arr = ret_arr + " " + ret_arr_tmp
					i++
				} else {
					var ProcInject_Execute_tmp_byte1 []byte
					var ProcInject_Execute_tmp_byte2 []byte
					var j int = i + 3
					for j < len(conf_data) {
						if conf_data[j] > 20 {
							ProcInject_Execute_tmp_byte1 = append(ProcInject_Execute_tmp_byte1, conf_data[j])
							j++
						} else {
							j++
						}
						if len(ProcInject_Execute_tmp_byte1) > 1 && conf_data[j] == 0x00 {
							break
						}
					}
					for j < len(conf_data) {
						if conf_data[j] > 20 {
							ProcInject_Execute_tmp_byte2 = append(ProcInject_Execute_tmp_byte2, conf_data[j])
							j++
						} else {
							j++
						}
						if len(ProcInject_Execute_tmp_byte2) > 1 && conf_data[j] == 0x00 {
							break
						}
					}
					ret_arr = fmt.Sprintln(string(ProcInject_Execute_tmp_byte1) + ":" + string(ProcInject_Execute_tmp_byte2))
					i = j + 1
				}
			}
		}
	}
	if p.isProcInjectTransform {
		var conf_data_tmp []byte = make([]byte, len(conf_data))
		if bytes.Compare(conf_data_tmp, conf_data) == 0 {
			return "Empty"
		}
		var ret_arr string
		var prepend_length uint32 = binary.BigEndian.Uint32(conf_data[0:4])
		var prepend []byte = conf_data[4 : 4+prepend_length]
		var append_length_offset uint32 = 4 + prepend_length
		var append_length uint32 = binary.BigEndian.Uint32(conf_data[append_length_offset : append_length_offset+4])
		var append []byte = conf_data[append_length_offset+4 : append_length_offset+4+append_length]
		for i := 0; i < len(prepend); i++ {
			ret_arr = ret_arr + fmt.Sprintf("\\x%x", prepend[i])
		}
		var append_length_byte []byte = make([]byte, 4)
		binary.BigEndian.PutUint32(append_length_byte, append_length)
		if append_length < 256 && bytes.Compare(append_length_byte, append) == 0 {
			ret_arr = ret_arr + " " + fmt.Sprintln(append)
		} else {
			ret_arr = ret_arr + " " + "Empty"
		}
		return ret_arr
	}
	if p.isMalleableStream {
		var prog string = ""
		var buf *bytes.Buffer = bytes.NewBuffer(conf_data)
		for {
			var op int = read_dword_be(buf, 4)
			if op == 0 {
				break
			} else if op == 1 {
				var l int = read_dword_be(buf, 4)
				prog = prog + " " + fmt.Sprintf("Remove %v bytes from the end", l)
			} else if op == 2 {
				var l int = read_dword_be(buf, 4)
				prog = prog + " " + fmt.Sprintf("Remove %v bytes from the beginning", l)
			} else if op == 3 {
				prog = prog + " " + fmt.Sprintf("Base64 decode")
			} else if op == 8 {
				prog = prog + " " + fmt.Sprintf("NetBIOS decode 'a'")
			} else if op == 11 {
				prog = prog + " " + fmt.Sprintf("NetBIOS decode 'A'")
			} else if op == 13 {
				prog = prog + " " + fmt.Sprintf("Base64 URL-safe decode")
			} else if op == 15 {
				prog = prog + " " + fmt.Sprintf("XOR mask w/ random key")
			}
		}
		return prog
	}
	if p.hashBlob {
		var x string = fmt.Sprintf("%x", md5.Sum(bytes.TrimRight(conf_data, "\x00")))
		return x
	}
	if p.isHeaders {
		var current_category string
		var trans map[string]string = map[string]string{
			"ConstHeaders": "",
			"ConstParams":  "",
			"Metadata":     "",
			"SessionId":    "",
			"Output":       "",
		}
		var TSTEPS map[int]string = map[int]string{
			1:  "append ",
			2:  "prepend ",
			3:  "base64 ",
			4:  "print ",
			5:  "parameter ",
			6:  "header ",
			7:  "build ",
			8:  "netbios ",
			9:  "const_parameter ",
			10: "const_header ",
			11: "netbiosu ",
			12: "uri_append ",
			13: "base64url ",
			14: "strrep ",
			15: "mask ",
			16: "const_host_header ",
		}
		var buf *bytes.Buffer = bytes.NewBuffer(conf_data)
		current_category = "Constants"
		var intarr []int = []int{1, 2, 5, 6}
		var intarr2 []int = []int{10, 16, 9}
		var intarr3 []int = []int{3, 4, 13, 8, 11, 12, 15}
		for {
			var tstep int = read_dword_be(buf, 4)
			if tstep == 7 {
				var name int = read_dword_be(buf, 4)
				if p.pos == 12 {
					current_category = "Metadata"
				} else {
					if name == 0 {
						current_category = "SessionId"
					} else {
						current_category = "Output"
					}
				}
			} else if IsContain(intarr, tstep) {
				var length int = read_dword_be(buf, 4)
				var c []byte = make([]byte, length)
				buf.Read(c)
				step_data := string(c)
				trans[current_category] = trans[current_category] + TSTEPS[tstep] + " \"" + step_data + "\""
			} else if IsContain(intarr2, tstep) {
				var length int = read_dword_be(buf, 4)
				var c []byte = make([]byte, length)
				buf.Read(c)
				var step_data string = string(c)
				if tstep == 9 {
					trans["ConstParams"] = trans["ConstParams"] + " " + step_data
				} else {
					trans["ConstHeaders"] = trans["ConstHeaders"] + " " + step_data
				}
			} else if IsContain(intarr3, tstep) {
				trans[current_category] = trans[current_category] + TSTEPS[tstep]
			} else {
				break
			}
		}
		if p.pos == 12 {
			p.transform_get = MapToJson(trans)
		} else {
			p.transform_post = MapToJson(trans)
		}
		return MapToJson(trans)
	}
	var conf_data_tmp []byte = bytes.TrimRight(conf_data, "\x00")
	return string(conf_data_tmp)
}

func MapToJson(param map[string]string) string {
	dataType, _ := json.Marshal(param)
	dataString := string(dataType) + "\r\n"
	return dataString
}

func read_dword_be(data *bytes.Buffer, length int) int {
	var c []byte = make([]byte, length)
	data.Read(c)
	return int(binary.BigEndian.Uint32(c))
}

func IsContain(items []int, item int) bool {
	var eachItem int
	for _, eachItem = range items {
		if eachItem == item {
			return true
		}
	}
	return false
}

func decode_config(data_buf []byte, version int) []byte {
	var XORBYTES byte
	if version == 3 {
		XORBYTES = 0x69
	} else if version == 4 {
		XORBYTES = 0x2e
	}
	var data_decode_buf []byte
	for i := 0; i < len(data_buf); i++ {
		data_decode_buf = append(data_decode_buf, data_buf[i]^XORBYTES) //0x2e是4版本的key 这里还没写兼容3的key
	}
	return data_decode_buf
}

func decrypt_beacon(buf []byte) []byte {
	var offset int = bytes.Index(buf, []byte("\xff\xff\xff"))
	if offset == -1 {
		return nil
	}

	offset += 3

	var key uint32 = binary.LittleEndian.Uint32(buf[offset : offset+4])
	//fmt.Println("key", key)

	//size := binary.LittleEndian.Uint32(buf[offset+4:offset+8]) ^ key
	//fmt.Println("size", size)

	var head_enc uint32 = binary.LittleEndian.Uint32(buf[offset+8:offset+12]) ^ key
	//fmt.Println("head_enc", head_enc)

	var head uint32 = head_enc & 0xffff
	//fmt.Println("head", head)

	if head == 0x5a4d || head == 0x9090 {

		var decoded_data []byte
		for i := offset/4 + 2; i <= len(buf)/4-4; i++ {
			var a uint32 = binary.LittleEndian.Uint32(buf[i*4 : i*4+4])
			//fmt.Println("a", a)

			var b uint32 = binary.LittleEndian.Uint32(buf[i*4+4 : i*4+8])
			//fmt.Println("b", b)

			var c uint32 = a ^ b
			//fmt.Println("c", c)

			var tmp []byte = make([]byte, 4)
			binary.LittleEndian.PutUint32(tmp, c)
			decoded_data = append(decoded_data, tmp...)

			//fmt.Println("decoded_data", decoded_data)
			// if i == 21 {
			// 	return decoded_data
			// }
		}
		return decoded_data
		//fmt.Println(confConsts)
	}

	return nil
}
