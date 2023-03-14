package main

import (
    "bytes"
    "errors"
    "encoding/hex"
    "crypto/des"
)

func ZeroPadding(ciphertext []byte, blockSize int) []byte {
    padding := blockSize - len(ciphertext)%blockSize
    padtext := bytes.Repeat([]byte{0}, padding)
    return append(ciphertext, padtext...)
}

func ZeroUnPadding(origData []byte) []byte {
    return bytes.TrimFunc(origData,
        func(r rune) bool {
            return r == rune(0)
        })
}

func Encrypt(text string, key []byte) (string, error) {
    src := []byte(text)
    block, err := des.NewCipher(key)
    if err != nil {
        return "", err
    }
    bs := block.BlockSize()
    src = ZeroPadding(src, bs)
    if len(src)%bs != 0 {
        return "", errors.New("Need a multiple of the blocksize")
    }
    out := make([]byte, len(src))
    dst := out
    for len(src) > 0 {
        block.Encrypt(dst, src[:bs])
        src = src[bs:]
        dst = dst[bs:]
    }
    return hex.EncodeToString(out), nil
}

func Decrypt(decrypted string , key []byte) (string, error) {
    src, err := hex.DecodeString(decrypted)
    if err != nil {
        return "", err
    }
    block, err := des.NewCipher(key)
    if err != nil {
        return "", err
    }
    out := make([]byte, len(src))
    dst := out
    bs := block.BlockSize()
    if len(src)%bs != 0 {
        return "", errors.New("crypto/cipher: input not full blocks")
    }
    for len(src) > 0 {
        block.Decrypt(dst, src[:bs])
        src = src[bs:]
        dst = dst[bs:]
    }
    out = ZeroUnPadding(out)
    return string(out), nil
}


