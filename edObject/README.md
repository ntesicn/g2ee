# G2EE-加解密对象
- 更加便捷的进行hash运算处理和加解密处理

> 支持的hash运算类型
- 支持MD5,SHA1,SHA256,SHA512
- 支持HMAC

> 哈希运算DEMO

```Go
package main
import (
   "github.com/ntesicn/g2ee/edObject"
)

func main() {
    edObj := edObject.New()
    //需要注意 hash运算的输出类型目前只支持 OutType_HEX 和 OutType_BASE64
    md5Str := edObj.GetHash(edObject.HASHTYPE_MD5,"123456",edObject.OUTTYPE_HEX)
    fmt.Println(md5Str)
      //或者
      edObject.New().GetHash(edObject.HASHTYPE_MD5,"123456",edObject.OUTTYPE_HEX)
}

```


> 加解密
由于精力有限,目前只封装了AES_CBC_128,AES_CBC_192,AES_CBC_256

> AES加解密DEMO
```Go
package main
import (
   "github.com/ntesicn/g2ee/edObject"
)
func main() {
    edObj := edObject.New()
    
    // ecryptType string, input interface{}, secret interface{}, iv interface{}, paddingType string, outType string
    // 这个demo中"123456"为待加密内容  可以传入string 或者[]byte 不用考虑类型转换 直接传入即可
    // demo中"1234567890123456" 为密钥key 可以传入string 或者[]byte 不用考虑类型转换 直接传入即可
    // iv可以直接传入nil 也可以传入指定的偏移量 可以传入string 或者[]byte 不用考虑类型转换 直接传入即可
    // paddingType 为填充类型 edObject.PADDING_NONE edObject.PADDING_PKCS5 edObject.PADDING_PKCS7 edObject.PADDING_ZERO 
    // outType 为输出类型 edObject.OUTTYPE_HEX edObject.OUTTYPE_TEXT edObject.OUTTYPE_BINARY edObject.OUTTYPE_BASE64
    aesResult,err := edObj.Encrypt(edObject.AES_CBC_128,"123456","1234567890123456",nil,edObject.PADDING_PKCS5,edObj.OUTTYPE_HEX)
    //aesResult需要根据OutType进行断言

      // 或者
     aesResult,err := edObject.New().Encrypt(edObject.AES_CBC_128,"123456","1234567890123456",nil,edObject.PADDING_PKCS5,edObj.OUTTYPE_HEX)
}

```






