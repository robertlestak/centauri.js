package main

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	_ "crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"strings"
	"syscall/js"
	"time"
)

func genNewAESKey(l int) string {
	var klen int = 16
	if l > 0 {
		klen = l
	}
	key := make([]byte, klen)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		panic(err)
	}
	hk := hex.EncodeToString(key)
	return hk
}

func aesEncrypt(key []byte, raw []byte) (map[string]any, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ciphertext := aesgcm.Seal(nil, nonce, raw, nil)
	res := map[string]any{
		"nonce":      hex.EncodeToString(nonce),
		"ciphertext": hex.EncodeToString(ciphertext),
	}
	return res, nil
}

func aesDecrypt(kd []byte, nonce []byte, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(kd)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	raw, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

func generateKeyPair(this js.Value, args []js.Value) any {
	kp := map[string]any{
		"public":  nil,
		"private": nil,
		"error":   nil,
	}
	privatekey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		js.Global().Get("console").Call("log", "generateRSAKey error: "+err.Error())
		kp["error"] = err.Error()
		return kp
	}
	publickey := &privatekey.PublicKey

	// dump private key to file
	var privateKeyBytes []byte = x509.MarshalPKCS1PrivateKey(privatekey)
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	}
	privBytes := pem.EncodeToMemory(privateKeyBlock)
	// dump public key to file
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publickey)
	if err != nil {
		js.Global().Get("console").Call("log", "generateRSAKey error: "+err.Error())
		kp["error"] = err.Error()
		return kp
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	pubBytes := pem.EncodeToMemory(publicKeyBlock)
	kp["public"] = string(pubBytes)
	kp["private"] = string(privBytes)
	return kp
}
func HashSumMessage(msg []byte) []byte {
	// sha256 hash of message
	h := sha256.New()
	h.Write(msg)
	return h.Sum(nil)
}
func Sign(msg []byte, priv *rsa.PrivateKey) ([]byte, error) {
	// priv, err := keys.BytesToPrivKey(privKey)
	// if err != nil {
	// 	return nil, err
	// }
	hs := HashSumMessage(msg)
	return rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, hs)
}
func CreateSignature(this js.Value, args []js.Value) any {
	ts := time.Now().Unix()
	var td struct {
		Timestamp int64 `json:"timestamp"`
	}
	var sigReq struct {
		PublicKey []byte `json:"public_key"`
		Data      []byte `json:"data"`
		Signature []byte `json:"signature"`
	}
	td.Timestamp = ts
	jd, err := json.Marshal(td)
	if err != nil {
		return js.ValueOf(err.Error())
	}
	kstring := args[0].String()
	if kstring == "" {
		return js.ValueOf("no private key")
	}
	key, err := BytesToPrivKey([]byte(kstring))
	sig, err := Sign(jd, key)
	if err != nil {
		return js.ValueOf(err.Error())
	}
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return js.ValueOf(err.Error())
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyPem := pem.EncodeToMemory(publicKeyBlock)
	sigReq.PublicKey = publicKeyPem
	//log.Printf("public key: %s", publicKeyBlock)
	sigReq.Data = jd
	sigReq.Signature = sig
	j, err := json.Marshal(sigReq)
	if err != nil {
		return js.ValueOf(err.Error())
	}
	return js.ValueOf(base64.StdEncoding.EncodeToString(j))
}

func PubKeyID(pubKeyBytes []byte) string {
	// ensure pubKeyBytes has a trailing \n
	if !bytes.HasSuffix(pubKeyBytes, []byte{'\n'}) {
		pubKeyBytes = append(pubKeyBytes, '\n')
	}
	h := sha256.Sum256(pubKeyBytes)
	return fmt.Sprintf("%x", h[:])
}

func pubKeyID(this js.Value, args []js.Value) any {
	pubKeyString := args[0].String()
	pubKeyBytes := []byte(pubKeyString)
	return js.ValueOf(PubKeyID(pubKeyBytes))
}

func BytesToPubKey(publicKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, errors.New("public key error")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pub := pubInterface.(*rsa.PublicKey)
	return pub, nil
}

func BytesToPrivKey(privateKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		p, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, err
		}
		priv = p.(*rsa.PrivateKey)
	}
	return priv, nil
}

func rsaEncryptData(publicKey []byte, origData []byte) ([]byte, error) {
	pub, err := BytesToPubKey(publicKey)
	if err != nil {
		return nil, err
	}
	d, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, origData, nil)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func pubKeyFromPrivate(this js.Value, args []js.Value) any {
	priv, err := BytesToPrivKey([]byte(args[0].String()))
	if err != nil {
		return js.ValueOf(err.Error())
	}
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return js.ValueOf(err.Error())
	}
	publicKeyBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	}
	publicKeyPem := pem.EncodeToMemory(publicKeyBlock)
	return js.ValueOf(string(publicKeyPem))
}

func rsaDecryptData(privateKey []byte, ciphertext []byte) ([]byte, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		p, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, err
		}
		priv = p.(*rsa.PrivateKey)
	}
	d, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return d, nil
}

func createCentauriHeader(key string, nonce string, pubKey []byte) string {
	header := map[string]any{
		"k": key,
		"n": nonce,
	}
	jd, err := json.Marshal(header)
	if err != nil {
		return ""
	}

	enc, err := rsaEncryptData(pubKey, jd)
	if err != nil {
		return ""
	}
	return hex.EncodeToString(enc)
}

func handleDecryptHeader(privateKey []byte, ciphertext []byte) (map[string]string, error) {
	block, _ := pem.Decode(privateKey)
	if block == nil {
		return nil, errors.New("private key error")
	}
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		p, e := x509.ParsePKCS8PrivateKey(block.Bytes)
		if e != nil {
			return nil, err
		}
		priv = p.(*rsa.PrivateKey)
	}
	d, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	header := make(map[string]string)
	err = json.Unmarshal(d, &header)
	if err != nil {
		return nil, err
	}
	return header, nil
}

func createCentauriMessage(this js.Value, args []js.Value) any {
	k := genNewAESKey(16)
	hk, err := hex.DecodeString(k)
	if err != nil {
		return js.ValueOf(err.Error())
	}
	toPubKey := []byte(args[0].String())
	data := []byte(args[1].String())
	enc, err := aesEncrypt(hk, data)
	if err != nil {
		return js.ValueOf(err.Error())
	}
	hdr := createCentauriHeader(k, enc["nonce"].(string), toPubKey)
	if hdr == "" {
		return js.ValueOf("error creating header")
	}
	return js.ValueOf(hdr + "." + enc["ciphertext"].(string))
}

func decryptCentauriMessage(this js.Value, args []js.Value) any {
	privateKey := []byte(args[0].String())
	messageData := args[1].String()
	messageParts := strings.Split(messageData, ".")
	if len(messageParts) != 2 {
		return js.ValueOf("invalid message")
	}
	hdr := messageParts[0]
	ciphertext := messageParts[1]
	hdrData, err := hex.DecodeString(hdr)
	if err != nil {
		return js.ValueOf(err.Error())
	}
	header, err := handleDecryptHeader(privateKey, hdrData)
	if err != nil {
		return js.ValueOf(err.Error())
	}
	kd, err := hex.DecodeString(header["k"])
	if err != nil {
		return js.ValueOf(err.Error())
	}
	nd, err := hex.DecodeString(header["n"])
	if err != nil {
		return js.ValueOf(err.Error())
	}
	ct, err := hex.DecodeString(ciphertext)
	if err != nil {
		return js.ValueOf(err.Error())
	}
	dec, err := aesDecrypt(kd, nd, ct)
	if err != nil {
		return js.ValueOf(err.Error())
	}
	return js.ValueOf(string(dec))
}

func main() {
	done := make(chan struct{}, 0)
	js.Global().Set("Centauri_GenerateKeyPair", js.FuncOf(generateKeyPair))
	js.Global().Set("Centauri_CreateMessage", js.FuncOf(createCentauriMessage))
	js.Global().Set("Centauri_DecryptMessage", js.FuncOf(decryptCentauriMessage))
	js.Global().Set("Centauri_PubKeyFromPrivate", js.FuncOf(pubKeyFromPrivate))
	js.Global().Set("Centauri_CreateSignature", js.FuncOf(CreateSignature))
	js.Global().Set("Centauri_PubKeyID", js.FuncOf(pubKeyID))
	<-done
}
