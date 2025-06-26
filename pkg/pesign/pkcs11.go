package pesign

import (
	"crypto"
	"errors"
	"fmt"
	"github.com/ThalesGroup/crypto11"
	"log/slog"
	"net/url"
	"os"
	"strconv"
	"strings"
)

// loadPKCS11Signer loads a PKCS#11 signer from a URI.
// The URI should be in the format:
// pkcs11:module-path=<path>;pin-value=<pin>;token=<token-label>;slot-id=<slot-id>;id=<key-id>
// or
// pkcs11:module-path=<path>;pin-value=<pin>;object=<key-object-label>
// Looks like the required arguments are:
// - module-path: Path to the PKCS#11 module
// - pin-value: PIN for the token.
// TODO: We could also support passing the PIN via an environment variable for security, or dropping and asking for the PIN
// TODO: We should check which parameters are required and optional and so on, but looking and the config seems like we are covered
func loadPKCS11Signer(pkcs11uri string) (crypto.Signer, error) {
	slog.Debug("PKCS#11 URI input", "uri", pkcs11uri)
	uri, err := url.Parse(pkcs11uri)
	if err != nil {
		slog.Error("Failed to parse PKCS#11 URI", "error", err)
		return nil, err
	}

	slog.Debug("Parsed URI", "scheme", uri.Scheme, "opaque", uri.Opaque, "rawquery", uri.RawQuery)

	// Parse parameters from the opaque part (not query params)
	params := make(map[string]string)
	for _, param := range strings.Split(uri.Opaque, ";") {
		if param == "" {
			continue
		}
		kv := strings.SplitN(param, "=", 2)
		if len(kv) == 2 {
			params[kv[0]] = kv[1]
		}
	}
	slog.Debug("Parsed params from opaque", "params", params)

	modulePath := params["module-path"]
	pin := params["pin-value"]

	slog.Debug("Extracted module-path and pin-value", "module-path", modulePath, "pin-value", "***")

	if modulePath == "" || pin == "" {
		slog.Error("module-path and pin-value required in PKCS#11 URI", "module-path", modulePath, "pin-value", pin)
		return nil, errors.New("module-path and pin-value required in PKCS#11 URI")
	}

	conf := &crypto11.Config{
		Path: modulePath,
		Pin:  pin,
	}

	if tokenLabel, ok := params["token"]; ok {
		conf.TokenLabel = tokenLabel
	}
	if slotIDStr, ok := params["slot-id"]; ok {
		slotID, err := strconv.Atoi(slotIDStr)
		if err != nil {
			return nil, err
		}
		conf.SlotNumber = &slotID
	}

	// Check if the module file exists and log its permissions
	if stat, statErr := os.Stat(modulePath); statErr != nil {
		slog.Error("PKCS#11 module file not found", "path", modulePath, "statErr", statErr)
	} else {
		slog.Debug("PKCS#11 module file found", "path", modulePath, "mode", stat.Mode(), "size", stat.Size())
	}

	ctx, err := crypto11.Configure(conf)
	if err != nil {
		slog.Error("crypto11.Configure failed", "error", err, "errorDetails", fmt.Sprintf("%+v", err), "conf.Path", conf.Path, "conf.Pin", "***", "conf.TokenLabel", conf.TokenLabel, "conf.SlotNumber", conf.SlotNumber)
		return nil, err
	}

	var key crypto.Signer
	var idBytes []byte
	if id, ok := params["id"]; ok {
		// Try to decode as hex if it looks like hex
		if len(id)%2 == 0 {
			decoded, err := hex.DecodeString(id)
			if err == nil {
				idBytes = decoded
				slog.Debug("Decoded id as hex", "id", id, "idBytes", idBytes)
			} else {
				idBytes = []byte(id)
				slog.Debug("Failed to decode id as hex, using as ASCII bytes", "id", id, "idBytes", idBytes)
			}
			if hexOk {
				idBytes = decoded
				slog.Debug("Decoded id as hex", "id", id, "idBytes", idBytes)
			} else {
				idBytes = []byte(id)
				slog.Debug("Failed to decode id as hex, using as ASCII bytes", "id", id, "idBytes", idBytes)
			}
		} else {
			idBytes = []byte(id)
		}
	}
	if len(idBytes) > 0 {
		key, err = ctx.FindKeyPair(idBytes, nil)
		slog.Debug("Tried FindKeyPair by id", "idBytes", idBytes, "err", err)
		if err != nil {
			return nil, err
		}
		if key != nil {
			return key, nil
		}
	}
	if label, ok := params["object"]; ok {
		key, err = ctx.FindKeyPair(nil, []byte(label))
		slog.Debug("Tried FindKeyPair by label", "label", label, "err", err)
		if err != nil {
			return nil, err
		}
		if key != nil {
			return key, nil
		}
	}

	return nil, errors.New("no key found with specified ID or object label on PKCS#11 token")
}
