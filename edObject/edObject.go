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

type g2eeEDObject struct{}

func New() *g2eeEDObject {
	return &g2eeEDObject{}
}

const (
	HASHTYPE_MD5    = "MD5"
	HASHTYPE_SHA1   = "SHA1"
	HASHTYPE_SHA256 = "SHA256"
	HASHTYPE_SHA512 = "SHA512"

	OUTTYPE_HEX    = "HEX"
	OUTTYPE_BASE64 = "BASE64"
	OUTTYPE_BINARY = "BINARY"
	OUTTYPE_TEXT   = "TEXT"

	AES_CBC_128 = "AES_CBC_128"
	AES_CBC_192 = "AES_CBC_192"
	AES_CBC_256 = "AES_CBC_256"

	AES_ECB_128 = "AES_ECB_128"
	AES_ECB_192 = "AES_ECB_192"
	AES_ECB_256 = "AES_ECB_256"

	AES_CFB_128 = "AES_CFB_128"
	AES_CFB_192 = "AES_CFB_192"
	AES_CFB_256 = "AES_CFB_256"

	AES_OFB_128 = "AES_OFB_128"
	AES_OFB_192 = "AES_OFB_192"
	AES_OFB_256 = "AES_OFB_256"

	AES_CTR_128 = "AES_CTR_128"
	AES_CTR_192 = "AES_CTR_192"
	AES_CTR_256 = "AES_CTR_256"

	PADDING_PKCS5 = "pkcs5"
	PADDING_PKCS7 = "pkcs7"
	PADDING_ZERO  = "zero"
	PADDING_NONE  = "none"
)

/* 加解密对象 加密数据 公开 */
/* ecryptType 加密类型 AES_CBC_128/192/256 */
/* input 为待取摘要数据 可以string或[]byte */
/* secret 为加密密钥 可以string或[]byte */
/* iv 为加密向量 可以string或[]byte */
/* paddingType 为填充类型 PaddingType_None PaddingType_PKCS5 PaddingType_PKCS7 PaddingType_Zero */
/* outType 为输出类型 OutType_Hex OutType_Text OutType_Binary OutType_Base64 */
func (edobj *g2eeEDObject) Encrypt(ecryptType string, input interface{}, secret interface{}, iv interface{}, paddingType string, outType string) (interface{}, error) {
	switch ecryptType {
	case AES_CBC_128, AES_CBC_192, AES_CBC_256:

		return edobj.aesCBCEncrypt(ecryptType, input, secret, iv, paddingType, outType)

	default:
		//抛出错误
		return "", fmt.Errorf("未知的加密类型")
	}
}

/* AES_CBC 加密  内部 */
func (edobj *g2eeEDObject) aesCBCEncrypt(ecryptType string, input interface{}, secret interface{}, iv interface{}, paddingType string, outType string) (interface{}, error) {
	if paddingType == "" {
		paddingType = PADDING_NONE
	}
	if outType == "" {
		outType = OUTTYPE_HEX
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
	case AES_CBC_128:
		secretBin = ZeroPadding(secretBin, 16)
	case AES_CBC_192:
		secretBin = ZeroPadding(secretBin, 24)
	case AES_CBC_256:
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
		// 补全或截断IV长度
		if len(ivBin) < aes.BlockSize {
			ivBin = ZeroPadding(ivBin, aes.BlockSize)
		} else if len(ivBin) > aes.BlockSize {
			ivBin = ivBin[:aes.BlockSize]
		}

	}

	var ciphertext []byte
	switch paddingType {
	case PADDING_PKCS5:
		ciphertext = PKCS5Padding(inputBin, block.BlockSize())

	case PADDING_PKCS7:
		ciphertext = PKCS7Padding(inputBin, block.BlockSize())

	case PADDING_ZERO:
		ciphertext = ZeroPadding(inputBin, block.BlockSize())

	case PADDING_NONE:
		ciphertext = inputBin

	default:
		// 未知填充类型
		ciphertext = inputBin
	}
	CBC := cipher.NewCBCEncrypter(block, ivBin)
	CBC.CryptBlocks(ciphertext, ciphertext)
	switch outType {
	case OUTTYPE_HEX:
		return hex.EncodeToString(ciphertext), nil
	case OUTTYPE_BASE64:
		return base64.StdEncoding.EncodeToString(ciphertext), nil
	case OUTTYPE_BINARY:
		return ciphertext, nil
	default:
		return "", fmt.Errorf("未知OutType")
	}

}

/* 加解密对象 解密数据 公开 */
func (edobj *g2eeEDObject) Decrypt(ecryptType string, input interface{}, secret interface{}, iv interface{}, paddingType string, outType string) (interface{}, error) {
	switch ecryptType {
	case AES_CBC_128, AES_CBC_192, AES_CBC_256:

		return edobj.aesCBCDecrypt(ecryptType, input, secret, iv, paddingType, outType)

	default:
		return nil, fmt.Errorf("未知的解密类型")
	}

}

/* AES_CBC 解密  内部 */
func (edobj *g2eeEDObject) aesCBCDecrypt(ecryptType string, input interface{}, secret interface{}, iv interface{}, paddingType string, outType string) (interface{}, error) {
	if paddingType == "" {
		paddingType = PADDING_NONE
	}
	if outType == "" {
		outType = OUTTYPE_BINARY
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
	case AES_CBC_128:
		secretBin = ZeroPadding(secretBin, 16)
	case AES_CBC_192:
		secretBin = ZeroPadding(secretBin, 24)
	case AES_CBC_256:
		secretBin = ZeroPadding(secretBin, 32)
	}

	//断言 待解密内容
	var inputBin []byte
	switch input := input.(type) {
	case string:
		decodedInput, err := base64.StdEncoding.DecodeString(input)
		if err != nil {
			return nil, fmt.Errorf("base64解码失败: %v", err)
		}
		inputBin = decodedInput
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
		if len(ivBin) < aes.BlockSize {
			ivBin = ZeroPadding(ivBin, aes.BlockSize)
		} else if len(ivBin) > aes.BlockSize {
			ivBin = ivBin[:aes.BlockSize]
		}
	}

	mode := cipher.NewCBCDecrypter(block, ivBin)

	mode.CryptBlocks(inputBin, inputBin)

	switch paddingType {
	case PADDING_PKCS5:
		inputBin = PKCS5UnPadding(inputBin)
	case PADDING_PKCS7:
		inputBin, err = PKCS7UnPadding(inputBin)
		if err != nil {
			return nil, err
		}
	case PADDING_ZERO:
		inputBin = ZeroUnPadding(inputBin)
	case PADDING_NONE:
		break
	default:
		return nil, fmt.Errorf("未知填充类型")
	}

	switch outType {
	case OUTTYPE_HEX:
		return hex.EncodeToString(inputBin), nil
	case OUTTYPE_BASE64:
		return base64.StdEncoding.EncodeToString(inputBin), nil
	case OUTTYPE_BINARY:
		return inputBin, nil
	case OUTTYPE_TEXT:
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

func PKCS7UnPadding(origData []byte) ([]byte, error) {
	length := len(origData)
	if length == 0 {
		return nil, fmt.Errorf("解密数据为空或非法")
	}

	unpadding := int(origData[length-1])
	if unpadding > length {
		return nil, fmt.Errorf("解密错误，填充大小 %d 无效", unpadding)
	}

	return origData[:(length - unpadding)], nil
}

// 加解密对象 取哈希码
// hashType 使用edobj.HashType_ 前缀的常量
// input 为待取摘要数据 可以string或[]byte
// outType 使用edobj.OutType_ 前缀的常量
func (edobj *g2eeEDObject) GetHash(hashType string, input interface{}, outType string) string {
	var hash hash.Hash
	//判断hash类型 md5 sha1 sha128 sha256 sha512
	switch hashType {
	case HASHTYPE_MD5:
		hash = md5.New()
	case HASHTYPE_SHA1:
		hash = sha1.New()
	case HASHTYPE_SHA256:
		hash = sha256.New()
	case HASHTYPE_SHA512:
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

	if outType == OUTTYPE_HEX {
		return hex.EncodeToString(hashValue)
	} else if outType == OUTTYPE_BASE64 {
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
	case HASHTYPE_MD5:
		hash = hmac.New(md5.New, keybin)
	case HASHTYPE_SHA1:
		hash = hmac.New(sha1.New, keybin)
	case HASHTYPE_SHA256:
		hash = hmac.New(sha256.New, keybin)
	case HASHTYPE_SHA512:
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

	if outType == OUTTYPE_HEX {
		return hex.EncodeToString(hashValue)
	} else if outType == OUTTYPE_BASE64 {
		return base64.StdEncoding.EncodeToString(hashValue)
	}
	return ""
}
