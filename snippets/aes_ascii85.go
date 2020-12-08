package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/ascii85"
	"fmt"
	"io"
	"bytes"
	"io/ioutil"
	"strings"
)

func encode(buf []byte) string {
	out := bytes.NewBuffer(nil)
	enc := ascii85.NewEncoder(out)
	enc.Write(buf)
	enc.Close()
	return out.String()
}


func decode(buf string) []byte {
	decoder := ascii85.NewDecoder(strings.NewReader(buf))
	dbuf, _ := ioutil.ReadAll(decoder)
	return dbuf
}

func main() {
 	kbytes := make([]byte, 16) //generate a random 32 byte key for AES-256
 	if _, err := rand.Read(kbytes); err != nil {
 		panic(err.Error())
 	}
	key := encode(kbytes) //encode key in bytes to string and keep as secret, put in a vault
	fmt.Printf("key to encrypt/decrypt : %s\n", key)

	encrypted := encrypt("Hello Encrypt", key)
	fmt.Printf("encrypted : %s\n", encrypted)
	
	decrypted := decrypt(encrypted, key)
	fmt.Printf("decrypted : %s\n", decrypted)
}

func encrypt(stringToEncrypt string, keyString string) (encryptedString string) {
	//Since the key is in string, we need to convert decode it to bytes
	key := decode(keyString)
	plaintext := []byte(stringToEncrypt)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err.Error())
	}

	//Encrypt the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	return encode(ciphertext)
}

func decrypt(encryptedString string, keyString string) (decryptedString string) {
	key := decode(keyString)
	enc := decode(encryptedString)

	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err.Error())
	}

	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		panic(err.Error())
	}

	//Get the nonce size
	nonceSize := aesGCM.NonceSize()

	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]

	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		panic(err.Error())
	}

	return fmt.Sprintf("%s", plaintext)
}
