package pesign

import (
	"crypto"
	"errors"
	"github.com/ThalesGroup/crypto11"
	"net/url"
	"strconv"
	"strings"
)

// loadPKCS11Signer loads a PKCS#11 signer from a URI.
// The URI should be in the format:
// pkcs11:module-path=<path>;pin-value=<pin>;token=<token-label>;slot-id=<slot-id>;id=<key-id>
// or
// pkcs11:module-path=<path>;pin-value=<pin>;object=<key-object-label>
func loadPKCS11Signer(pkcs11uri string) (crypto.Signer, error) {
	uri, err := url.Parse(pkcs11uri)
	if err != nil {
		return nil, err
	}

	params := uri.Query()

	modulePath := params.Get("module-path")
	pin := params.Get("pin-value")

	if modulePath == "" || pin == "" {
		return nil, errors.New("module-path and pin-value required in PKCS#11 URI")
	}

	conf := &crypto11.Config{
		Path: modulePath,
		Pin:  pin,
	}

	tokenParams := strings.Split(uri.Opaque, ";")
	for _, param := range tokenParams {
		if strings.HasPrefix(param, "token=") {
			conf.TokenLabel = strings.TrimPrefix(param, "token=")
		} else if strings.HasPrefix(param, "slot-id=") {
			slotID, err := strconv.Atoi(strings.TrimPrefix(param, "slot-id="))
			if err != nil {
				return nil, err
			}
			conf.SlotNumber = &slotID
		}
	}

	ctx, err := crypto11.Configure(conf)
	if err != nil {
		return nil, err
	}

	var key crypto.Signer
	for _, param := range tokenParams {
		if strings.HasPrefix(param, "id=") {
			idHex := strings.TrimPrefix(param, "id=")
			keyID, err := url.PathUnescape(idHex)
			if err != nil {
				return nil, err
			}
			key, err = ctx.FindKeyPair(nil, []byte(keyID))
			if err != nil {
				return nil, err
			}
			if key == nil {
				return nil, errors.New("no key found with specified ID on PKCS#11 token")
			}
			return key, nil
		}
		if strings.HasPrefix(param, "object=") {
			label := strings.TrimPrefix(param, "object=")
			key, err = ctx.FindKeyPair([]byte(label), nil)
			if err != nil {
				return nil, err
			}
			if key == nil {
				return nil, errors.New("no key found with specified object label on PKCS#11 token")
			}
			return key, nil
		}
	}

	return nil, errors.New("no valid key identifier (id= or object=) provided in PKCS#11 URI")
}
