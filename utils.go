package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"errors"
)

// base64decode is a shortcut to make it easier to remember
func base64decode(data string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(data)
}

// decrypt attempts to decrypt the data with aes-cbc
func decrypt(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)

	ret := make([]byte, len(data))
	blockMode.CryptBlocks(ret, data)

	return unpad(ret, block.BlockSize())
}

// unpad is needed because this is how openssl pads aes-128-cbc, so we
// need to unpad as well in order to properly decrypt the data. Note
// that this should conform to PCKS#7.
func unpad(data []byte, blocksize int) ([]byte, error) {
	if blocksize <= 0 {
		return nil, errors.New("Invalid block size")
	}

	if data == nil || len(data) == 0 {
		return nil, errors.New("Invalid data")
	}

	if len(data)%blocksize != 0 {
		return nil, errors.New("Input is not a multiple of blocksize")
	}

	lastByte := data[len(data)-1]
	padSize := int(lastByte)
	if padSize == 0 || padSize > len(data) {
		return nil, errors.New("Invalid pad size")
	}

	padding := data[len(data)-padSize:]
	for _, b := range padding {
		if b != lastByte {
			return nil, errors.New("Invalid padding")
		}
	}

	return data[:len(data)-padSize], nil
}

func deriveKey(password []byte, salt []byte) (key []byte, iv []byte) {
	rounds := 2
	data := append(password, salt...)
	md5Hashes := make([][]byte, rounds)
	sum := md5.Sum(data)

	md5Hashes[0] = append([]byte{}, sum[:]...)

	for i := 1; i < rounds; i++ {
		sum = md5.Sum(append(md5Hashes[i-1], data...))
		md5Hashes[i] = append([]byte{}, sum[:]...)
	}

	return md5Hashes[0], md5Hashes[1]
}
