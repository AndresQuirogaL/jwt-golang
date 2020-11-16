package jwt

import (
	"fmt"
	"log"
	"crypto"
	"strings"

	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"

)


func Base64Encode(input string) string {
    return strings.
        TrimRight(base64.URLEncoding.
            EncodeToString([]byte(input)), "=")
}


func Base64Decode(input string) (string, error) {
	rem := len(input) % 4

	if rem > 0 {
		input += strings.Repeat("=", 4 - rem)
	}

    decoded, err := base64.URLEncoding.DecodeString(input)

    if err != nil {
        errMsg := fmt.Errorf("Decoding Error %s", err)
        return "", errMsg
    }
    return string(decoded), nil
}


func Encode(header string, payload string, privateKeyBytes []byte, pass string) (string, error) {
	headerEnc := Base64Encode(header)
	payloadEnc := Base64Encode(payload)

	rng := rand.Reader

	message := headerEnc + "." + payloadEnc
	messageBytes := []byte(message)
	hashed := sha256.Sum256(messageBytes)

    block, _ := pem.Decode(privateKeyBytes)

	if "RSA PRIVATE KEY" != block.Type {
		log.Fatal("CA Private Key Type %s", block.Type)
	}

	var keyBytes []byte

	if x509.IsEncryptedPEMBlock(block) {
		keyBytes, _ = x509.DecryptPEMBlock(block, []byte(pass))
	} else {
		fmt.Println(" *** No password")
		keyBytes = block.Bytes
	}

	privKey, err := x509.ParsePKCS1PrivateKey(keyBytes)

	if err != nil {
		log.Fatal("Cannot parse PrivateKey %s", err)
		return "", err
	}

	signature, err := rsa.SignPKCS1v15(rng, privKey, crypto.SHA256, hashed[:])
	signatureEnc := Base64Encode(string(signature))

	if err != nil {
		log.Fatal("Error from signing: %s\n", err)
		return "", err
	}

	jwt := message + "." + signatureEnc

	return jwt, nil
}


func Verify(jwtToken string, publicKeyBytes []byte) {
	block, _ := pem.Decode(publicKeyBytes)

	if "PUBLIC KEY" != block.Type {
		log.Fatal("CA Public Key Type %s", block.Type)
		return
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)

	if err != nil {
		log.Fatal("Cannot parse Public Key %s", err)
		return
	}

	tokenParts := strings.Split(jwtToken, ".")

	headerSegment := tokenParts[0]
	payloadSegment := tokenParts[1]
	cryptoSegment := tokenParts[2]

	message := headerSegment + "." + payloadSegment
	messageBytes := []byte(message)
	hashed := sha256.Sum256(messageBytes)

	signature, err := Base64Decode(cryptoSegment)

	if err != nil {
		log.Fatal("Error decoding cryptoSegment: %s", err)
	}

	err = rsa.VerifyPKCS1v15(
		pubKey.(*rsa.PublicKey),
		crypto.SHA256,
		hashed[:],
		[]byte(signature),
	)

	if err != nil {
		log.Fatal("Error from verification: %s", err)
	} else {
		fmt.Println("Verified!!!")
	}
}
