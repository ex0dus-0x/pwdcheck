package kdf

import (
    "net/url"
    "crypto/sha1"
    "crypto/sha256"

    "golang.org/x/crypto/pbkdf2"
)

type PwdGenerator struct {
    hash [32]byte
    domain string
}

// instantiates a new generator for key derivation and
// password generation for a given password
func NewGenerator(pwd string, url_string string) (*PwdGenerator, error) {

    // initialize SHA256 hash from password
    hash := sha256.Sum256([]byte(pwd))

    // initialize salt from domain name
    u, err := url.Parse(url_string)
    if err != nil {
        return nil, err
    }
    host := u.Host

    // initialize generator to return
    generator := &PwdGenerator {
        hash: hash,
        domain: host,
    }
    return generator, nil
}

// does one round of key-generation using PBKDF2 and returns the resultant
// derived key for consumption.
func (g PwdGenerator) GenerateKey() [32]byte {
    derivedKey := pbkdf2.Key(g.hash, []byte(g.domain), 10, 64, sha1.New)
    return sha256.Sum256(derivedKey)
}
