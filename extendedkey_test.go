package hdwallet

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestMasterDeterministicVector(t *testing.T) {
	seed := mustHex(t, "000102030405060708090a0b0c0d0e0f")
	master, err := NewMaster(seed)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := hex.EncodeToString(master.key), "a06a97b52af6fff00be4c4ed75c95ad3f2d0c2cb4f00479c3cd3357259d5cb4ffa907a23207bd40b3d0479212b80c38536bbfc2edb91afa34e5c13db4fb5b652"; got != want {
		t.Fatalf("master private key = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(master.chainCode[:]), "5875ad2aacf5fdf2c6af80087ca701684d97856ffd530e2891c3d5eed54f82a1"; got != want {
		t.Fatalf("master chain code = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(master.PublicKey()), "672cee7ab7a38df97244109abd4aafb28593d6bef3735256ccf6f90e8537db59"; got != want {
		t.Fatalf("master public key = %s, want %s", got, want)
	}
}

func TestPrivateAndPublicNonHardenedDerivationMatch(t *testing.T) {
	account, err := newTestMaster(t).DerivePath("m/44'/0'")
	if err != nil {
		t.Fatal(err)
	}

	privateChild, err := account.Derive(7)
	if err != nil {
		t.Fatal(err)
	}
	publicChild, err := account.Neuter().Derive(7)
	if err != nil {
		t.Fatal(err)
	}

	if got, want := hex.EncodeToString(publicChild.PublicKey()), hex.EncodeToString(privateChild.PublicKey()); got != want {
		t.Fatalf("public-derived child = %s, want %s", got, want)
	}

	msg := []byte("transaction")
	sig := privateChild.Sign(msg)
	if !ed25519.Verify(publicChild.PublicKey(), msg, sig) {
		t.Fatal("public-derived child did not verify private-derived child signature")
	}
}

func TestDeepDerivationDeterministicVector(t *testing.T) {
	key, err := newTestMaster(t).DerivePath("m/44'/1815'/0'/0/27")
	if err != nil {
		t.Fatal(err)
	}

	if got, want := hex.EncodeToString(key.PrivateKey()), "5fd6e0c11d06c1cfd032dfd57905749c34b3c3cbcac755a2888be88cc6034203a51f7fe857e57988eb36e057992c732bda46e05cea9ca584261dad2071efd23c"; got != want {
		t.Fatalf("derived private key = %s, want %s", got, want)
	}
	if got, want := hex.EncodeToString(key.PublicKey()), "7ad8f348998c16f19535ced914689180ff053190705602b1060bd69d4ae05f37"; got != want {
		t.Fatalf("derived public key = %s, want %s", got, want)
	}
}

func TestPublicKeyRejectsHardenedDerivation(t *testing.T) {
	publicKey := newTestMaster(t).Neuter()

	if _, err := publicKey.Derive(Hardened(0)); !errors.Is(err, ErrHardenedPublicChild) {
		t.Fatalf("public hardened derive error = %v, want ErrHardenedPublicChild", err)
	}
}

func TestNilAndInvalidKeys(t *testing.T) {
	var key *ExtendedKey
	if _, err := key.Derive(0); !errors.Is(err, ErrNilKey) {
		t.Fatalf("nil Derive error = %v, want ErrNilKey", err)
	}
	if _, err := key.DerivePath("m/0"); !errors.Is(err, ErrNilKey) {
		t.Fatalf("nil DerivePath error = %v, want ErrNilKey", err)
	}
	if key.PublicKey() != nil {
		t.Fatal("nil PublicKey returned key")
	}
	if key.PrivateKey() != nil {
		t.Fatal("nil PrivateKey returned key")
	}
	if key.Sign([]byte("msg")) != nil {
		t.Fatal("nil Sign returned signature")
	}
	if key.Neuter() != nil {
		t.Fatal("nil Neuter returned key")
	}
	if key.IsPrivate() {
		t.Fatal("nil IsPrivate returned true")
	}
	if key.copy() != nil {
		t.Fatal("nil copy returned key")
	}

	badPrivate := &ExtendedKey{key: []byte{1, 2, 3}, isPrivate: true}
	if badPrivate.PublicKey() != nil {
		t.Fatal("bad private PublicKey returned key")
	}
	if badPrivate.PrivateKey() != nil {
		t.Fatal("bad private PrivateKey returned key")
	}
	if badPrivate.Sign([]byte("msg")) != nil {
		t.Fatal("bad private Sign returned signature")
	}
	if _, err := badPrivate.Derive(0); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("bad private Derive error = %v, want ErrInvalidKey", err)
	}

	badPublic := &ExtendedKey{key: []byte{1, 2, 3}}
	if badPublic.PublicKey() != nil {
		t.Fatal("bad public PublicKey returned key")
	}
	if _, err := badPublic.Derive(0); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("bad public Derive error = %v, want ErrInvalidKey", err)
	}
}

func TestDerivePath(t *testing.T) {
	master := newTestMaster(t)

	fromPath, err := master.DerivePath("m/44'/1815'/0'/0/1")
	if err != nil {
		t.Fatal(err)
	}
	manual, err := master.Derive(Hardened(44))
	if err != nil {
		t.Fatal(err)
	}
	manual, err = manual.Derive(Hardened(1815))
	if err != nil {
		t.Fatal(err)
	}
	manual, err = manual.Derive(Hardened(0))
	if err != nil {
		t.Fatal(err)
	}
	manual, err = manual.Derive(0)
	if err != nil {
		t.Fatal(err)
	}
	manual, err = manual.Derive(1)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(fromPath.key), hex.EncodeToString(manual.key); got != want {
		t.Fatalf("path key = %s, want %s", got, want)
	}
}

func TestPublicDerivePath(t *testing.T) {
	account, err := newTestMaster(t).DerivePath("m/44'/0'/0'")
	if err != nil {
		t.Fatal(err)
	}
	privateChild, err := account.DerivePath("m/0/5")
	if err != nil {
		t.Fatal(err)
	}
	publicChild, err := account.Neuter().DerivePath("m/0/5")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := hex.EncodeToString(publicChild.PublicKey()), hex.EncodeToString(privateChild.PublicKey()); got != want {
		t.Fatalf("public path child = %s, want %s", got, want)
	}
	if _, err := account.Neuter().DerivePath("m/0/5'"); !errors.Is(err, ErrHardenedPublicChild) {
		t.Fatalf("public hardened path error = %v, want ErrHardenedPublicChild", err)
	}
}

func TestDerivePathRejectsInvalidPaths(t *testing.T) {
	master := newTestMaster(t)
	invalid := []string{
		"",
		" m/0",
		"n/0",
		"m//0",
		"m/-1",
		"m/+1",
		"m/2147483648",
		"m/1''",
	}

	for _, path := range invalid {
		if _, err := master.DerivePath(path); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("DerivePath(%q) error = %v, want ErrInvalidPath", path, err)
		}
	}
}

func TestSerializationRoundTrip(t *testing.T) {
	key, err := newTestMaster(t).DerivePath("m/44'/0'/0'/0/1")
	if err != nil {
		t.Fatal(err)
	}

	encoded := key.String()
	if !strings.HasPrefix(encoded, privateStringPrefix) {
		t.Fatalf("private string prefix = %q", encoded[:5])
	}

	parsed, err := ParseExtendedKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !parsed.IsPrivate() {
		t.Fatal("parsed private key reported public")
	}
	if parsed.String() != encoded {
		t.Fatalf("private round trip = %q, want %q", parsed.String(), encoded)
	}

	publicEncoded := key.Neuter().String()
	if !strings.HasPrefix(publicEncoded, publicStringPrefix) {
		t.Fatalf("public string prefix = %q", publicEncoded[:5])
	}
	publicParsed, err := ParseExtendedKey(publicEncoded)
	if err != nil {
		t.Fatal(err)
	}
	if publicParsed.IsPrivate() {
		t.Fatal("parsed public key reported private")
	}
	if got, want := hex.EncodeToString(publicParsed.PublicKey()), hex.EncodeToString(key.PublicKey()); got != want {
		t.Fatalf("public key = %s, want %s", got, want)
	}
}

func TestSerializationRejectsInvalidInput(t *testing.T) {
	key := newTestMaster(t).String()
	corrupt := key[:len(key)-1] + "1"
	if _, err := ParseExtendedKey("xprv" + key); !errors.Is(err, ErrInvalidSerialization) {
		t.Fatalf("wrong prefix error = %v, want ErrInvalidSerialization", err)
	}
	if _, err := ParseExtendedKey(corrupt); err == nil {
		t.Fatal("corrupt checksum parsed without error")
	}
	if _, err := ParseExtendedKey("edprv0"); !errors.Is(err, ErrInvalidSerialization) {
		t.Fatalf("invalid base58 error = %v, want ErrInvalidSerialization", err)
	}
	if _, err := ParseExtendedKey("edprv1"); !errors.Is(err, ErrInvalidSerialization) {
		t.Fatalf("short payload error = %v, want ErrInvalidSerialization", err)
	}
	payload := newTestMaster(t).serialize()
	payload[0] = 0xff
	if _, err := ParseExtendedKey("edprv" + base58CheckEncode(payload)); !errors.Is(err, ErrInvalidSerialization) {
		t.Fatalf("unknown version error = %v, want ErrInvalidSerialization", err)
	}
	payload = newTestMaster(t).serialize()
	payload[45] = 0xff
	if _, err := ParseExtendedKey("edprv" + base58CheckEncode(payload)); !errors.Is(err, ErrInvalidSerialization) {
		t.Fatalf("bad private marker error = %v, want ErrInvalidSerialization", err)
	}
	pubPayload := newTestMaster(t).Neuter().serialize()
	pubPayload[45] = 0xff
	if _, err := ParseExtendedKey("edpub" + base58CheckEncode(pubPayload)); !errors.Is(err, ErrInvalidSerialization) {
		t.Fatalf("bad public marker error = %v, want ErrInvalidSerialization", err)
	}
}

func TestSignAndVerify(t *testing.T) {
	key, err := newTestMaster(t).DerivePath("m/44'/0'/0'/0/1")
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello")
	sig := key.Sign(msg)
	if !ed25519.Verify(key.PublicKey(), msg, sig) {
		t.Fatal("signature did not verify")
	}
	if key.Neuter().Sign(msg) != nil {
		t.Fatal("public key signed message")
	}
}

func TestReturnedKeyMaterialIsCopied(t *testing.T) {
	key := newTestMaster(t)
	pub := key.PublicKey()
	priv := key.PrivateKey()
	pub[0] ^= 0xff
	priv[0] ^= 0xff

	if hex.EncodeToString(key.PublicKey()) == hex.EncodeToString(pub) {
		t.Fatal("PublicKey returned mutable internal state")
	}
	if hex.EncodeToString(key.PrivateKey()) == hex.EncodeToString(priv) {
		t.Fatal("PrivateKey returned mutable internal state")
	}
}

func TestConcurrentUseIsDeterministic(t *testing.T) {
	key := newTestMaster(t)
	const workers = 32

	results := make(chan string, workers)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			child, err := key.DerivePath("m/44'/0'/0'/0/1")
			if err != nil {
				t.Errorf("DerivePath: %v", err)
				return
			}
			results <- hex.EncodeToString(child.PublicKey())
		})
	}
	wg.Wait()
	close(results)

	var first string
	for result := range results {
		if first == "" {
			first = result
			continue
		}
		if result != first {
			t.Fatalf("non-deterministic concurrent result: %s != %s", result, first)
		}
	}
}

func TestNewMasterValidatesSeedLength(t *testing.T) {
	for _, seed := range [][]byte{make([]byte, minSeedBytes-1), make([]byte, maxSeedBytes+1)} {
		if _, err := NewMaster(seed); !errors.Is(err, ErrInvalidSeed) {
			t.Fatalf("NewMaster length %d error = %v, want ErrInvalidSeed", len(seed), err)
		}
	}
}

func TestHelpers(t *testing.T) {
	digest := ripemd160([]byte("abc"))
	if got := hex.EncodeToString(digest[:]); got != "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc" {
		t.Fatalf("ripemd160(abc) = %s", got)
	}
	if got := base58Encode([]byte{0, 0, 1}); got != "112" {
		t.Fatalf("base58Encode leading zeros = %s", got)
	}
	if decoded, err := base58Decode("112"); err != nil || hex.EncodeToString(decoded) != "000001" {
		t.Fatalf("base58Decode = %x, %v", decoded, err)
	}
	if cloneBytes(nil) != nil {
		t.Fatal("cloneBytes(nil) returned non-nil")
	}
}

func newTestMaster(t *testing.T) *ExtendedKey {
	t.Helper()
	key, err := NewMaster(make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
