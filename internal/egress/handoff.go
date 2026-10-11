package egress

import "errors"

// VerifyStoredCredentials validates the original AAD and endpoint identity in
// memory. It never exports plaintext, rewrites ciphertext or changes an ID.
func VerifyStoredCredentials(key []byte, station, org, id, endpoint string, input Input, encrypted []byte) error {
	if len(key) != 32 {
		return errors.New("handoff credentials invalid")
	}
	a, e := newCipher(key)
	if e != nil {
		return errors.New("handoff credentials invalid")
	}
	c, e := unseal(a, encrypted, station+":"+org+":"+id)
	if e != nil || !validCredentials(c) || endpointKey(input, c) != endpoint {
		return errors.New("handoff credentials invalid")
	}
	original := input
	if _, e = normalize(&input); e != nil || input.Name != original.Name || input.Host != original.Host {
		return errors.New("handoff endpoint invalid")
	}
	return nil
}
