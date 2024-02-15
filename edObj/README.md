# G2EE-加解密对象
- 更加便捷的进行hash运算处理和加解密处理

> 支持的hash运算类型
- 支持MD5,SHA1,SHA256,SHA512
- 支持HMAC

> 哈希运算DEMO

```Go
package main
import (
   G2EE_EDOBJ "github.com/ntesicn/g2ee/edObj"
)

func main() {
    edObj := G2EE_EDOBJ.New()
    //需要注意 hash运算的输出类型目前只支持 OutType_HEX 和 OutType_BASE64
    md5Str := edObj.GetHash(edObj.HashType_MD5,"123456",edObj.OutType_HEX)
    fmt.Println(md5Str)
}

```


> 加解密
由于精力有限,目前只封装了AES_CBC_128,AES_CBC_192,AES_CBC_256

> AES加解密DEMO
```Go
package main
import (
    G2EE_EDOBJ "github.com/ntesicn/g2ee/edObj"
)
func main() {
    edObj := G2EE_EDOBJ.New()
    
    // ecryptType string, input interface{}, secret interface{}, iv interface{}, paddingType string, outType string
    // 这个demo中"123456"为待加密内容  可以传入string 或者[]byte 不用考虑类型转换 直接传入即可
    // demo中"1234567890123456" 为密钥key 可以传入string 或者[]byte 不用考虑类型转换 直接传入即可
    // iv可以直接传入nil 也可以传入指定的偏移量 可以传入string 或者[]byte 不用考虑类型转换 直接传入即可
    // paddingType 为填充类型 edObj.PaddingType_None edObj.PaddingType_PKCS5 edObj.PaddingType_PKCS7 edObj.PaddingType_Zero 
    // outType 为输出类型 edObj.OutType_Hex edObj.OutType_Text edObj.OutType_Binary edObj.OutType_Base64
    aesResult,err := edObj.Encrypt(edObj.AES_CBC_128,"123456","1234567890123456",nil,edObj.PaddingType_PKCS5,edObj.OutType_HEX)
    //aesResult需要根据OutType进行断言
}

```






