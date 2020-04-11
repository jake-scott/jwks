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
type keySpec struct {
	keyid   string
	keyfile string
}

type keySpecs []keySpec

func (s *keySpecs) String() string {
	var rets []string

	for _, ks := range *s {
		this := fmt.Sprintf("File:%s", ks.keyfile)
		if ks.keyid != "" {
			this += fmt.Sprintf(" (Key ID: %s)", ks.keyid)
		}

		rets = append(rets, this)
	}
	return strings.Join(rets, ",")
}

func (s *keySpecs) Set(val string) error {
	parts := strings.SplitN(val, ":", 2)

	var ks keySpec

	if len(parts) > 1 {
		ks.keyid = parts[0]
		ks.keyfile = parts[1]
	} else {
		ks.keyfile = parts[0]
	}

	*s = append(*s, ks)
	return nil
}

func Usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage of %s:\n", os.Args[0])
	fmt.Fprintf(flag.CommandLine.Output(), "%s <options> <file>...:\n", os.Args[0])
	flag.PrintDefaults()
}

func init() {
	flag.Usage = Usage
}

/* End string list command line glue */

type jwks struct {
	Keys []jwk.Key `json:"keys"`
}

type args struct {
	files keySpecs
}

func parseCmdLine() (args args, err error) {
	flag.Var(&args.files, "k", "keyid:cert, used to override a Key ID (may use multiple times)")

	err = flag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		return
	}

	for _, s := range flag.Args() {
		args.files = append(args.files, keySpec{keyfile: s})
	}

	if len(args.files) == 0 {
		return args, fmt.Errorf("Must specify one or more cert/key files")
	}
	return
}

// Parse a file containing one or more X509 certs or keys, returning
// the JWT representations
func parseFile(file keySpec) (keys []jwk.Key, err error) {
	keyData, err := ioutil.ReadFile(file.keyfile)
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
			if file.keyid == "" {
				// Default the key ID to the key thumbprint
				if key.KeyID() == "" {
					sum, err := key.Thumbprint(crypto.SHA1)
					if err != nil {
						return nil, err
					}
					fp := base64.RawURLEncoding.EncodeToString(sum[:])

					key.Set(jwk.KeyIDKey, fp)
				}
			} else {
				key.Set(jwk.KeyIDKey, file.keyid)
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
