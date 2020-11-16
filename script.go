package main

import (
	"log"
	"fmt"
	
	"io/ioutil"
	jwt "jwt"
)

func main() {
    // ENCODE EXAMPLE.
    rawHeader := "{\"alg\":\"RS256\",\"typ\":\"JWT\"}"
    rawPayload := "{\"sub\":\"1234567890\"}"
	privateKey, err := ioutil.ReadFile("jwt_keys/jwt-key.pem")
	pass := "te3455gggd1235"

	if err != nil {
		log.Fatal(err)
	}

    jwtToken, err := jwt.Encode(rawHeader, rawPayload, privateKey, pass)

	if err != nil {
		log.Fatal(err)
	}

    // VERIFY EXAMPLE.
    fmt.Println("jwtToken: ", jwtToken)

	publicKey, err := ioutil.ReadFile("jwt_keys/jwt-key.pub")

	if err != nil {
		log.Fatal(err)
	}

    jwt.Verify(jwtToken, publicKey)
}
