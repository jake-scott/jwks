package main

/*
 * Generate a JSON Web Key Set from a set of PEM encoded certificates and/or keys
 * read from files
 */

import (
	"crypto"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/jwk"
)

/*
 * For command line processing of a set of strings
 */
type stringList []string

func (s *stringList) String() string {
	return strings.Join(*s, ",")
}

func (s *stringList) Set(val string) error {
	*s = append(*s, val)
	return nil
}

/* End string list command line glue */

type jwks struct {
	Keys []jwk.Key `json:"keys"`
}

type args struct {
	files stringList
}

func parseCmdLine() (args args, err error) {
	flag.Var(&args.files, "f", "Certificate or key file (may use multiple times)")

	err = flag.CommandLine.Parse(os.Args[1:])

	if len(args.files) == 0 {
		return args, fmt.Errorf("Must specify one or more cert/key files")
	}
	return
}

// Parse a file containing one or more X509 certs or keys, returning
// the JWT representations
func parseFile(file string) (keys []jwk.Key, err error) {
	keyData, err := ioutil.ReadFile(file)
	if err != nil {
		return
	}

	for block, rest := pem.Decode(keyData); block != nil; block, rest = pem.Decode(rest) {
		var key jwk.Key

		switch block.Type {
		case "CERTIFICATE":
			// Parse the raw data
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, err
			}

			key, err = jwk.New(cert.PublicKey)
			if err != nil {
				return nil, err
			}

			// Fingerprint of the cert, not the public key it contains
			sum := sha1.Sum(cert.Raw)
			fp := base64.RawURLEncoding.EncodeToString(sum[:])
			key.Set(jwk.KeyIDKey, fp)

		case "PUBLIC KEY":
			pkey, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			key, err = jwk.New(pkey)
			if err != nil {
				return nil, err
			}
		case "RSA PUBLIC KEY":
			pkey, err := x509.ParsePKCS1PublicKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			key, err = jwk.New(pkey)
			if err != nil {
				return nil, err
			}
		case "EC PRIVATE KEY":
			pkey, err := x509.ParseECPrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			key, err = jwk.New(pkey)
			if err != nil {
				return nil, err
			}
		case "RSA_PRIVATE_KEY":
			pkey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			key, err = jwk.New(pkey)
			if err != nil {
				return nil, err
			}
		case "PRIVATE_KEY":
			pkey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, err
			}
			key, err = jwk.New(pkey)
			if err != nil {
				return nil, err
			}
		}

		if key != nil {
			// Default the key ID to the key thumbprint
			if key.KeyID() == "" {
				sum, err := key.Thumbprint(crypto.SHA1)
				if err != nil {
					return nil, err
				}
				fp := base64.RawURLEncoding.EncodeToString(sum[:])

				key.Set(jwk.KeyIDKey, fp)
			}
			keys = append(keys, key)
		}
	}

	return
}

func main() {
	args, err := parseCmdLine()
	if err != nil {
		log.Fatal(err)
	}

	var keySet jwks

	for _, file := range args.files {
		keys, err := parseFile(file)
		if err != nil {
			log.Fatal(err)
		}

		keySet.Keys = append(keySet.Keys, keys...)
	}

	b, err := json.MarshalIndent(keySet, "", "  ")
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(b))
}
