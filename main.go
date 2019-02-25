package main

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/BurntSushi/toml"
	"log"
	"math"
	"strconv"
	"strings"
	"time"
)

type GAuth struct {
	codeLen float64
}

type Conf struct {
	Secret string
}
var Config Conf

func NewGAuth() *GAuth {
	return &GAuth{
		codeLen: 6,
	}
}

func HmacSha1(key, data []byte) []byte {
	mac := hmac.New(sha1.New, key)
	mac.Write(data)
	return mac.Sum(nil)
}

func (gAuth *GAuth) GetCode(secret string, timeSlices ...int64) (string, error) {
	var timeSlice int64
	switch len(timeSlices) {
	case 0:
		timeSlice = time.Now().Unix() / 30
	case 1:
		timeSlice = timeSlices[0]
	default:
		return "", errors.New("param error")
	}
	secret = strings.ToUpper(secret)
	secretKey, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", err
	}
	tim, err := hex.DecodeString(fmt.Sprintf("%016x", timeSlice))
	if err != nil {
		return "", err
	}
	hm := HmacSha1(secretKey, tim)
	offset := hm[len(hm)-1] & 0x0F
	hashpart := hm[offset : offset+4]
	value, err := strconv.ParseInt(hex.EncodeToString(hashpart), 16, 0)
	if err != nil {
		return "", err
	}
	value = value & 0x7FFFFFFF
	modulo := int64(math.Pow(10, gAuth.codeLen))
	format := fmt.Sprintf("%%0%dd", int(gAuth.codeLen))
	return fmt.Sprintf(format, value%modulo), nil
}

func main()  {
	_, err := toml.DecodeFile("conf.toml", &Config)
	if err != nil {
		log.Fatalln(err)
	}

	gauth := NewGAuth()

	token, err := gauth.GetCode(Config.Secret)
	fmt.Println(token)
}
