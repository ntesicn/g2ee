package qiniu

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"
)

type Qiniu struct {
	AccessKey string `json:"accessKey"`
	SecretKey string `json:"secretKey"`
	Bucket    string `json:"bucket"`
	Domain    string `json:"domain"`
}

func New(accessKey string, secretKey string, bucket string, domain string) *Qiniu {
	return &Qiniu{
		AccessKey: accessKey,
		SecretKey: secretKey,
		Bucket:    bucket,
		Domain:    domain,
	}
}

// 构造期望响应格式
func (qn *Qiniu) CreateUploadPolicy(title string, code int, msg string, show_key bool, show_hash bool) interface{} {
	domain := qn.Domain
	if domain[len(domain)-1:] == "/" {
		domain = domain[:len(domain)-1]
	}
	if title == "" {
		title = "$(key)"
	}
	if msg == "" {
		msg = "success"
	}
	if code == 0 {
		code = 0
	}
	if !show_key {
		show_key = true
	}
	if !show_hash {
		show_hash = true
	}

	data := make(map[string]interface{})
	data["src"] = domain + "/$(key)"
	data["title"] = title

	returnBody := make(map[string]interface{})
	returnBody["code"] = code
	returnBody["msg"] = msg
	returnBody["data"] = data
	if show_key == true {
		returnBody["key"] = "$(key)"
	}
	if show_hash == true {
		returnBody["hash"] = "$(etag)"
	}

	return returnBody
}

// 创建七牛云上传凭证
func (qn *Qiniu) CreateUploadToken(Expire int64, returnBody interface{}) string {

	Jzb := make(map[string]interface{})
	if data, ok := returnBody.(map[string]interface{}); ok {
		if data["data"] != nil && data["data"].(map[string]interface{})["title"] != "" {
			Jzb["scope"] = qn.Bucket + ":" + data["data"].(map[string]interface{})["title"].(string)
		} else {
			Jzb["scope"] = qn.Bucket
		}
	} else {
		// 处理returnBody不是map[string]interface{}类型的情况
		return ""
	}

	Jzb["deadline"] = Expire
	if returnBody != nil {
		returnBodyStr, err := json.Marshal(returnBody)
		if err != nil {
			fmt.Println("Error:", err)
			return err.Error()
		}
		fmt.Println(string(returnBodyStr))
		Jzb["returnBody"] = string(returnBodyStr)
	}
	jsonData, err := json.Marshal(Jzb)
	if err != nil {
		fmt.Println("Error:", err)
		return err.Error()
	}
	fmt.Println(string(jsonData))
	encodedPutPolicy := base64.URLEncoding.EncodeToString([]byte(jsonData))

	encodedSign := base64.URLEncoding.EncodeToString(HmacSha1([]byte(qn.SecretKey), []byte(encodedPutPolicy)))

	if encodedSign == "" {
		return ""
	}

	return qn.AccessKey + ":" + encodedSign + ":" + encodedPutPolicy
}
func HmacSha1(key []byte, data []byte) []byte {
	h := hmac.New(sha1.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func (qn *Qiniu) CreateDownLoad(link string, effectiveTime int64) string {
	// 解析URL以检查是否已存在有效期参数
	parsedUrl, err := url.Parse(link)
	if err != nil {
		fmt.Println("URL parsing error:", err)
		return ""
	}
	queryParams := parsedUrl.Query()
	expireStr := queryParams.Get("e")

	if expireStr != "" {
		// 如果存在有效期参数，尝试解析并判断是否即将过期
		expire, err := strconv.ParseInt(expireStr, 10, 64)
		if err != nil {
			fmt.Println("Error parsing expire time:", err)
			return ""
		}
		if time.Now().Unix() < expire-60 {
			// 如果有效期还未到一分钟前，直接返回原URL
			return link
		}
	}

	// 如果没有有效期参数或有效期即将过期，重新计算有效期
	expire := time.Now().Add(time.Duration(effectiveTime) * time.Second).Unix()
	urlStr := parsedUrl.Scheme + "://" + parsedUrl.Host + parsedUrl.Path + "?e=" + fmt.Sprintf("%d", expire)
	encodedSign := base64.URLEncoding.EncodeToString(HmacSha1([]byte(qn.SecretKey), []byte(urlStr)))
	Token := qn.AccessKey + ":" + encodedSign
	urlStr = urlStr + "&token=" + Token
	return urlStr
}
