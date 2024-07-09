package httpClient // 网站客户端

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type g2eeHttpClient struct {
	client  *http.Client
	resData []byte
}

func New() *g2eeHttpClient {
	return &g2eeHttpClient{
		client: &http.Client{
			Timeout: time.Duration(20) * time.Second,
		},
	}
}
func (c *g2eeHttpClient) ChangeTimeout(timeout int) {
	// 通过指针修改 client.Timeout 的值
	c.client.Timeout = time.Duration(timeout) * time.Second
}

func (c *g2eeHttpClient) GetResBin() []byte {
	return c.resData
}

func (c *g2eeHttpClient) GetResString() string {
	return string(c.resData)
}

func (c *g2eeHttpClient) POST(url string, body interface{}, headers map[string]string) error {
	var req *http.Request
	//断言body类型
	switch body.(type) {
	case string:
		req, _ = http.NewRequest("POST", url, strings.NewReader(body.(string)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	case []byte:
		req, _ = http.NewRequest("POST", url, bytes.NewBuffer(body.([]byte)))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	// body如果是map则提交json
	case map[string]interface{}:
		//body转为json文本
		JSONEncode := func(m map[string]interface{}) []byte {
			b, _ := json.Marshal(m)
			return b
		}

		req, _ = http.NewRequest("POST", url, bytes.NewBuffer(JSONEncode(body.(map[string]interface{}))))
		req.Header.Set("Content-Type", "application/json")

	default:
		return errors.New("body type error")
	}
	//设置header
	if headers != nil {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		c.resData = body
		return nil
	} else {
		return errors.New("http status code is " + fmt.Sprintf("%d", resp.StatusCode))
	}

}

func (c *g2eeHttpClient) GET(url string, query interface{}, headers map[string]string) error {
	if query != nil {
		//断言query类型
		switch query.(type) {
		case string:
			url = url + "?" + query.(string)
		case []byte:
			url = url + "?" + string(query.([]byte))
		case map[string]interface{}:
			url = url + "?"
			//query转为formdata表达那格式
			for k, v := range query.(map[string]interface{}) {
				url = url + k + "=" + fmt.Sprintf("%v", v) + "&"
			}
			url = strings.TrimRight(url, "&")

		default:
			return errors.New("query type error")
		}
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}
	if headers != nil {
		for k, v := range headers {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == 200 {
		body, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		} else {
			c.resData = body
			return nil
		}
	} else {
		return errors.New("http status code is " + fmt.Sprintf("%d", resp.StatusCode))
	}
}

// map转表单formdata
func (c *g2eeHttpClient) Map2FormData(m map[string]interface{}) string {
	var buffer bytes.Buffer
	i := 0
	for k, v := range m {
		i++
		buffer.WriteString(k)
		buffer.WriteString("=")
		buffer.WriteString(fmt.Sprintf("%v", v))
		if i < len(m) {
			buffer.WriteString("&")
		}

	}
	return buffer.String()
}
