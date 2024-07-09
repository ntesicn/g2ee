package edObject

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"hash"
)

type g2eeEDObject struct {
	HashType_MD5    string
	HashType_SHA1   string
	HashType_SHA256 string
	HashType_SHA512 string

	OutType_Hex    string
	OutType_Base64 string
	OutType_Binary string
	OutType_Text   string

	AES_CBC_128 string
	AES_CBC_192 string
	AES_CBC_256 string

	AES_ECB_128 string
	AES_ECB_192 string
	AES_ECB_256 string

	AES_CFB_128 string
	AES_CFB_192 string
	AES_CFB_256 string

	AES_OFB_128 string
	AES_OFB_192 string
	AES_OFB_256 string

	AES_CTR_128 string
	AES_CTR_192 string
	AES_CTR_256 string

	PaddingType_PKCS5 string
	PaddingType_PKCS7 string
	PaddingType_Zero  string
	PaddingType_None  string
}

func New() *g2eeEDObject {
	return &g2eeEDObject{
		HashType_MD5:    "md5",
		HashType_SHA1:   "sha1",
		HashType_SHA256: "sha256",
		HashType_SHA512: "sha512",

		OutType_Hex:    "hex",
		OutType_Base64: "base64",
		OutType_Binary: "binary",
		OutType_Text:   "text",

		AES_CBC_128: "AES_CBC_128",
		AES_CBC_192: "AES_CBC_192",
		AES_CBC_256: "AES_CBC_256",

		AES_ECB_128: "AES_ECB_128",
		AES_ECB_192: "AES_ECB_192",
		AES_ECB_256: "AES_ECB_256",

		AES_CFB_128: "AES_CFB_128",
		AES_CFB_192: "AES_CFB_192",
		AES_CFB_256: "AES_CFB_256",

		AES_OFB_128: "AES_OFB_128",
		AES_OFB_192: "AES_OFB_192",
		AES_OFB_256: "AES_OFB_256",

		AES_CTR_128: "AES_CTR_128",
		AES_CTR_192: "AES_CTR_192",
		AES_CTR_256: "AES_CTR_256",

		PaddingType_PKCS5: "pkcs5",
		PaddingType_PKCS7: "pkcs7",
		PaddingType_Zero:  "zero",
		PaddingType_None:  "none",
	}
}

/* 加解密对象 加密数据 公开 */
/* ecryptType 加密类型 AES_CBC_128/192/256 */
/* input 为待取摘要数据 可以string或[]byte */
/* secret 为加密密钥 可以string或[]byte */
/* iv 为加密向量 可以string或[]byte */
/* paddingType 为填充类型 PaddingType_None PaddingType_PKCS5 PaddingType_PKCS7 PaddingType_Zero */
/* outType 为输出类型 OutType_Hex OutType_Text OutType_Binary OutType_Base64 */
func (edobj *g2eeEDObject) Encrypt(ecryptType string, input interface{}, secret interface{}, iv interface{}, paddingType string, outType string) (interface{}, error) {
	switch ecryptType {
	case edobj.AES_CBC_128, edobj.AES_CBC_192, edobj.AES_CBC_256:

		return edobj.aesCBCEncrypt(ecryptType, input, secret, iv, paddingType, outType)

	default:
		//抛出错误
		return "", fmt.Errorf("未知的加密类型")
	}
}

/* AES_CBC 加密  内部 */
func (edobj *g2eeEDObject) aesCBCEncrypt(ecryptType string, input interface{}, secret interface{}, iv interface{}, paddingType string, outType string) (interface{}, error) {
	if paddingType == "" {
		paddingType = edobj.PaddingType_None
	}
	if outType == "" {
		outType = edobj.OutType_Hex
	}
	// 断言 secret
	var secretBin []byte
	switch secret := secret.(type) {
	case string:
		secretBin = []byte(secret)
	case []byte:
		secretBin = secret
	default:
		return "", fmt.Errorf("密码只能为string或[]byte")
	}
	//根据ecryptType使用ZeroPadding补全密码长度
	switch ecryptType {
	case edobj.AES_CBC_128:
		secretBin = ZeroPadding(secretBin, 16)
	case edobj.AES_CBC_192:
		secretBin = ZeroPadding(secretBin, 24)
	case edobj.AES_CBC_256:
		secretBin = ZeroPadding(secretBin, 32)
	}

	//断言 待加密内容
	var inputBin []byte
	switch input := input.(type) {
	case string:
		inputBin = []byte(input)
	case []byte:
		inputBin = input
	default:
		return "", fmt.Errorf("待加密内容只能为string或[]byte")
	}

	// AES_CBC 加密
	block, err := aes.NewCipher(secretBin)
	if err != nil {
		fmt.Println(err)
		return "", err
	}
	//断言IV
	var ivBin []byte
	if iv == nil {
		ivBin = make([]byte, aes.BlockSize)
	} else {
		switch iv := iv.(type) {
		case string:
			ivBin = []byte(iv)
		case []byte:
			ivBin = iv
		default:
			return "", fmt.Errorf("IV只能为string或[]byte")
		}
		//补全IV长度
		ivBin = ZeroPadding(ivBin, aes.BlockSize)
	}

	var ciphertext []byte
	switch paddingType {
	case edobj.PaddingType_PKCS5:
		ciphertext = PKCS5Padding(inputBin, block.BlockSize())

	case edobj.PaddingType_PKCS7:
		ciphertext = PKCS7Padding(inputBin, block.BlockSize())

	case edobj.PaddingType_Zero:
		ciphertext = ZeroPadding(inputBin, block.BlockSize())

	case edobj.PaddingType_None:
		ciphertext = inputBin

	default:
		// 未知填充类型
		ciphertext = inputBin
	}
	CBC := cipher.NewCBCEncrypter(block, ivBin)
	CBC.CryptBlocks(ciphertext, ciphertext)
	switch outType {
	case edobj.OutType_Hex:
		return hex.EncodeToString(ciphertext), nil
	case edobj.OutType_Base64:
		return base64.StdEncoding.EncodeToString(ciphertext), nil
	case edobj.OutType_Binary:
		return ciphertext, nil
	default:
		return "", fmt.Errorf("未知OutType")
	}

}

/* 加解密对象 解密数据 公开 */
func (edobj *g2eeEDObject) Decrypt(ecryptType string, input interface{}, secret interface{}, iv interface{}, paddingType string, outType string) (interface{}, error) {
	switch ecryptType {
	case edobj.AES_CBC_128, edobj.AES_CBC_192, edobj.AES_CBC_256:

		return edobj.aesCBCDecrypt(ecryptType, input, secret, iv, paddingType, outType)

	default:
		return nil, fmt.Errorf("未知的解密类型")
	}

}

/* AES_CBC 解密  内部 */
func (edobj *g2eeEDObject) aesCBCDecrypt(ecryptType string, input interface{}, secret interface{}, iv interface{}, paddingType string, outType string) (interface{}, error) {
	if paddingType == "" {
		paddingType = edobj.PaddingType_None
	}
	if outType == "" {
		outType = edobj.OutType_Binary
	}
	// 断言 secret
	var secretBin []byte
	switch secret := secret.(type) {
	case string:
		secretBin = []byte(secret)
	case []byte:
		secretBin = secret
	default:
		return nil, fmt.Errorf("密码只能为string或[]byte")
	}

	//根据ecryptType使用ZeroPadding补全密码长度
	switch ecryptType {
	case edobj.AES_CBC_128:
		secretBin = ZeroPadding(secretBin, 16)
	case edobj.AES_CBC_192:
		secretBin = ZeroPadding(secretBin, 24)
	case edobj.AES_CBC_256:
		secretBin = ZeroPadding(secretBin, 32)
	}

	//断言 待解密内容
	var inputBin []byte
	switch input := input.(type) {
	case string:
		inputBin = []byte(input)
	case []byte:
		inputBin = input
	default:
		return nil, fmt.Errorf("待解密内容只能为string或[]byte")
	}

	block, err := aes.NewCipher(secretBin)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	//断言IV
	var ivBin []byte
	if iv == nil {
		ivBin = make([]byte, aes.BlockSize)
	} else {
		switch iv := iv.(type) {
		case string:
			ivBin = []byte(iv)
		case []byte:
			ivBin = iv
		default:
			return nil, fmt.Errorf("IV只能为string或[]byte或nil")
		}
		ivBin = ZeroPadding(ivBin, aes.BlockSize)
	}

	mode := cipher.NewCBCDecrypter(block, ivBin)
	mode.CryptBlocks(inputBin, inputBin)

	switch paddingType {
	case edobj.PaddingType_PKCS5:
		inputBin = PKCS5UnPadding(inputBin)
	case edobj.PaddingType_PKCS7:
		inputBin = PKCS7UnPadding(inputBin)
	case edobj.PaddingType_Zero:
		inputBin = ZeroUnPadding(inputBin)
	case edobj.PaddingType_None:
		break
	default:
		return nil, fmt.Errorf("未知填充类型")
	}

	switch outType {
	case edobj.OutType_Hex:
		return hex.EncodeToString(inputBin), nil
	case edobj.OutType_Base64:
		return base64.StdEncoding.EncodeToString(inputBin), nil
	case edobj.OutType_Binary:
		return inputBin, nil
	case edobj.OutType_Text:
		return string(inputBin), nil
	default:
		return nil, fmt.Errorf("未知OutType")
	}

}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func ZeroPadding(ciphertext []byte, targetSize int) []byte {
	padding := targetSize - len(ciphertext)
	if padding < 0 {
		return ciphertext
	}
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func ZeroUnPadding(origData []byte) []byte {
	return bytes.TrimFunc(origData, func(r rune) bool {
		return r == rune(0)
	})
}

func PKCS7Padding(ciphertext []byte, blocksize int) []byte {
	padding := blocksize - len(ciphertext)%blocksize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// 加解密对象 取哈希码
// hashType 使用edobj.HashType_ 前缀的常量
// input 为待取摘要数据 可以string或[]byte
// outType 使用edobj.OutType_ 前缀的常量
func (edobj *g2eeEDObject) GetHash(hashType string, input interface{}, outType string) string {
	var hash hash.Hash
	//判断hash类型 md5 sha1 sha128 sha256 sha512
	switch hashType {
	case edobj.HashType_MD5:
		hash = md5.New()
	case edobj.HashType_SHA1:
		hash = sha1.New()
	case edobj.HashType_SHA256:
		hash = sha256.New()
	case edobj.HashType_SHA512:
		hash = sha512.New()
	default:
		return ""
	}
	//断言input类型
	switch input := input.(type) {
	case string:
		hash.Write([]byte(input))
	case []byte:
		hash.Write(input)
	default:
		return ""
	}
	hashValue := hash.Sum(nil)

	if outType == edobj.OutType_Hex {
		return hex.EncodeToString(hashValue)
	} else if outType == edobj.OutType_Base64 {
		return base64.StdEncoding.EncodeToString(hashValue)
	}
	return ""
}

// 加解密对象 取HMAC
func (dbobj *g2eeEDObject) GetHMAC(hashType string, input interface{}, key interface{}, outType string) string {
	var keybin []byte
	//断言key类型
	switch key := key.(type) {
	case string:
		keybin = []byte(key)
	case []byte:
		keybin = key
	default:
		return ""
	}

	var hash hash.Hash
	//判断hash类型 md5 sha1 sha128 sha256 sha512
	switch hashType {
	case dbobj.HashType_MD5:
		hash = hmac.New(md5.New, keybin)
	case dbobj.HashType_SHA1:
		hash = hmac.New(sha1.New, keybin)
	case dbobj.HashType_SHA256:
		hash = hmac.New(sha256.New, keybin)
	case dbobj.HashType_SHA512:
		hash = hmac.New(sha512.New, keybin)
	default:
		return ""
	}

	//断言input类型
	switch input := input.(type) {
	case string:
		hash.Write([]byte(input))
	case []byte:
		hash.Write(input)
	default:
		return ""
	}

	hashValue := hash.Sum(nil)

	if outType == dbobj.OutType_Hex {
		return hex.EncodeToString(hashValue)
	} else if outType == dbobj.OutType_Base64 {
		return base64.StdEncoding.EncodeToString(hashValue)
	}
	return ""
}
