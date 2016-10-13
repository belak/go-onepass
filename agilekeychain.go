package main

import (
	"crypto/sha1"
	"encoding/json"
	"errors"
	"log"
	"os"
	"path"

	"golang.org/x/crypto/pbkdf2"

	"github.com/Unknwon/com"
)

// AgileKeychain represents a 1password vault in the form of a
// .agilekeychain file.
type AgileKeychain struct {
	baseDir string
}

// AgileEntry represents a vault entry. This can be anything.
type AgileEntry struct {
	KeyID string
	// ...
	UUID string
	// ...
	SecurityLevel string
	// ...
	Title string
	// ...
	Encrypted string
}

type agileContents []agileContentsEntryContainer
type agileContentsEntryContainer []interface{}

type agileEncryptionKeys struct {
	// Currently only SL3 and SL5 exist, but more could be added in
	// the future. It seems like these match the identifier in the key
	// list, so it may be better to ignore these and just match
	// against the Level or the identifier directly in the list.
	SL3 string
	SL5 string

	List []agileEncryptionKey
}

type agileEncryptionKey struct {
	Level           string
	LevelIdentifier string `json:"identifier"`
	Validation      string // TODO: Not sure what this is
	Data            string
	Iterations      int
}

// NewAgileKeychain creates an AgileKeychain but does not unlock the
// vault.
func NewAgileKeychain(path string) (*AgileKeychain, error) {
	ret := &AgileKeychain{
		baseDir: path,
	}

	if !com.IsDir(ret.baseDir) {
		return nil, errors.New("Not a valid agilekeychain")
	}

	return ret, nil
}

func (k *AgileKeychain) Lookup(name, password string) (*AgileEntry, error) {
	contents, err := k.loadContents()
	if err != nil {
		return nil, err
	}

	ret := &AgileEntry{}

	for _, v := range *contents {
		if v[2] != name {
			continue
		}

		entry, err := k.loadPassword(v[0].(string))
		if err != nil {
			return nil, err
		}

		key, err := k.GetKey(entry.KeyID, password)
		if err != nil {
			return nil, err
		}

		rawPassword, err := base64decode(entry.Encrypted)
		if err != nil {
			return nil, err
		}

		passwordSalt := rawPassword[8:16]
		passwordData := rawPassword[16:]

		passwordKey, passwordIv := deriveKey(key, passwordSalt)

		data, err := decrypt(passwordData, passwordKey, passwordIv)
		if err != nil {
			return nil, err
		}

		log.Println(string(data))

		// Now that we have the entry we need to decode the data.

		// TODO: This makes it impossible to find items with
		// duplicate names.
		return ret, nil
	}

	return nil, errors.New("Entry not found")
}

func (k *AgileKeychain) loadContents() (*agileContents, error) {
	contentsPath := path.Join(k.baseDir, "data", "default", "contents.js")
	f, err := os.Open(contentsPath)
	if err != nil {
		return nil, err
	}

	ret := &agileContents{}
	err = json.NewDecoder(f).Decode(&ret)
	return ret, err
}

func (k *AgileKeychain) loadPassword(uuid string) (*AgileEntry, error) {
	entryPath := path.Join(k.baseDir, "data", "default", uuid+".1password")
	f, err := os.Open(entryPath)
	if err != nil {
		return nil, err
	}

	ret := &AgileEntry{}
	err = json.NewDecoder(f).Decode(&ret)
	return ret, err
}

func (k *AgileKeychain) GetKey(securityIdentifier, password string) ([]byte, error) {
	keys, err := k.loadKeys()
	if err != nil {
		return nil, err
	}

	for _, key := range keys.List {
		if key.LevelIdentifier != securityIdentifier {
			continue
		}

		rawKey, err := base64decode(key.Data)
		if err != nil {
			return nil, err
		}

		// Encrypted key data is salted. To determine if key is salted you can compare
		// its first 8 bytes "Salted__". The rest 8 bytes are actual salt data.
		keySalt := rawKey[8:16]
		keyData := rawKey[16:]

		derivedKey := pbkdf2.Key([]byte(password), []byte(keySalt), key.Iterations, 32, sha1.New)

		aesKey := derivedKey[0:16]
		aesIv := derivedKey[16:32]

		keyRaw, err := decrypt([]byte(keyData), aesKey, aesIv)
		if err != nil {
			return nil, err
		}

		return keyRaw, nil
	}

	return nil, errors.New("Key not found")
}

func (k *AgileKeychain) loadKeys() (*agileEncryptionKeys, error) {
	keysPath := path.Join(k.baseDir, "data", "default", "encryptionKeys.js")
	f, err := os.Open(keysPath)
	if err != nil {
		return nil, err
	}

	ret := &agileEncryptionKeys{}
	err = json.NewDecoder(f).Decode(&ret)
	return ret, err
}
