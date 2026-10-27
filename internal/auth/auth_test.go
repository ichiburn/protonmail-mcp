package auth

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

func TestZeroBytes(t *testing.T) {
	secret := []byte("super-secret-salted-key-passphrase-12345")
	if bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatal("expected initial slice to be non-zero")
	}
	ZeroBytes(secret)
	for i, b := range secret {
		if b != 0 {
			t.Fatalf("byte at index %d was not zeroed: got %d", i, b)
		}
	}
	ZeroBytes(nil)
	ZeroBytes([]byte{})
}

func TestGenerateTOTPCode_RFC6238VectorsAndNormalization(t *testing.T) {
	seed := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	code59, err := GenerateTOTPCode(seed, time.Unix(59, 0))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code59 != "287082" {
		t.Fatalf("expected RFC6238 vector 287082 at T=59, got %s", code59)
	}

	code111, err := GenerateTOTPCode("gezd gnbv gy3t qojq gezd gnbv gy3t qojq", time.Unix(1111111109, 0))
	if err != nil {
		t.Fatalf("unexpected error with lowercase/spaces: %v", err)
	}
	if code111 != "081804" {
		t.Fatalf("expected RFC6238 vector 081804 at T=1111111109, got %s", code111)
	}

	rfcVectors := []struct {
		unix int64
		want string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, v := range rfcVectors {
		got, err := GenerateTOTPCode(seed, time.Unix(v.unix, 0))
		if err != nil || got != v.want {
			t.Fatalf("RFC6238 vector unix=%d: got %q (err=%v), want %q", v.unix, got, err, v.want)
		}
	}

	codeUnpadded, err := GenerateTOTPCode(" jbsw y3dp ehpk 3pxp ", time.Unix(1700000000, 0))
	if err != nil {
		t.Fatalf("unexpected error on unpadded secret: %v", err)
	}
	if len(codeUnpadded) != 6 {
		t.Fatalf("expected 6-digit code, got %q", codeUnpadded)
	}
}

func TestGenerateTOTPCode_InvalidInputs(t *testing.T) {
	cases := []struct {
		name   string
		secret string
	}{
		{"empty", ""},
		{"spaces_only", "    "},
		{"invalid_base32_chars", "INVALID!@#$1890"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := GenerateTOTPCode(tc.secret, time.Now()); err == nil {
				t.Fatalf("expected error for invalid secret %q, got nil", tc.secret)
			}
		})
	}
}

func TestResolveTOTPInput(t *testing.T) {
	now := time.Unix(59, 0)
	// Direct 6-digit code
	code, err := ResolveTOTPInput(" 654321 ", now)
	if err != nil || code != "654321" {
		t.Fatalf("expected direct 6-digit code 654321, got %q (err=%v)", code, err)
	}
	// Base32 secret seed
	codeFromSeed, err := ResolveTOTPInput("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", now)
	if err != nil || codeFromSeed != "287082" {
		t.Fatalf("expected derived code 287082, got %q (err=%v)", codeFromSeed, err)
	}
	// Empty input rejected
	if _, err := ResolveTOTPInput("   ", now); err == nil {
		t.Fatal("expected error for empty 2FA input")
	}
}

type mockKeyringBackend struct {
	mu      sync.Mutex
	data    map[string]string
	failErr error
}

func newMockKeyringBackend(failErr error) *mockKeyringBackend {
	return &mockKeyringBackend{
		data:    make(map[string]string),
		failErr: failErr,
	}
}

func (m *mockKeyringBackend) Set(service, user, password string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failErr != nil {
		return m.failErr
	}
	m.data[service+":"+user] = password
	return nil
}

func (m *mockKeyringBackend) Get(service, user string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failErr != nil {
		return "", m.failErr
	}
	v, ok := m.data[service+":"+user]
	if !ok {
		return "", keyring.ErrNotFound
	}
	return v, nil
}

func (m *mockKeyringBackend) Delete(service, user string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failErr != nil {
		return m.failErr
	}
	key := service + ":" + user
	if _, ok := m.data[key]; !ok {
		return keyring.ErrNotFound
	}
	delete(m.data, key)
	return nil
}

func TestKeyringStore_SaveLoadUpdateDelete(t *testing.T) {
	backend := newMockKeyringBackend(nil)
	store := NewKeyringStore(backend, "protonmail-mcp-test", "acct")

	// Initially not found
	if _, err := store.Load(); !errors.Is(err, ErrCredentialsNotFound) {
		t.Fatalf("expected ErrCredentialsNotFound, got %v", err)
	}

	origKeyPass := []byte("salted-key-passphrase-bytes-32b!")
	creds := &StoredCredentials{
		UID:           "uid-initial-123",
		RefreshToken:  "refresh-initial-456",
		SaltedKeyPass: origKeyPass,
		UserID:        "user-1",
		Email:         "user@proton.me",
		DisplayName:   "Proton User",
	}

	if err := store.Save(creds); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	loaded, err := store.Load()
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if loaded.UID != "uid-initial-123" || loaded.RefreshToken != "refresh-initial-456" {
		t.Fatalf("unexpected loaded tokens: %+v", loaded)
	}
	if !bytes.Equal(loaded.SaltedKeyPass, origKeyPass) {
		t.Fatalf("SaltedKeyPass mismatch: got %q", loaded.SaltedKeyPass)
	}

	// Token rotation via UpdateTokens
	if err := UpdateTokens(store, "uid-rotated-789", "refresh-rotated-999"); err != nil {
		t.Fatalf("UpdateTokens failed: %v", err)
	}
	rotated, err := store.Load()
	if err != nil {
		t.Fatalf("Load after UpdateTokens failed: %v", err)
	}
	if rotated.UID != "uid-rotated-789" || rotated.RefreshToken != "refresh-rotated-999" {
		t.Fatalf("expected rotated tokens, got %+v", rotated)
	}
	if !bytes.Equal(rotated.SaltedKeyPass, origKeyPass) {
		t.Fatal("expected SaltedKeyPass to be preserved across token rotation")
	}

	// Zeroing loaded credentials clears SaltedKeyPass in memory
	rotated.Zero()
	for i, b := range rotated.SaltedKeyPass {
		if b != 0 {
			t.Fatalf("expected SaltedKeyPass byte %d to be 0 after Zero(), got %d", i, b)
		}
	}

	// Delete removes credentials
	if err := store.Delete(); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := store.Load(); !errors.Is(err, ErrCredentialsNotFound) {
		t.Fatalf("expected ErrCredentialsNotFound after Delete, got %v", err)
	}
}

func TestFileStore_Permissions0600EnforcementAndRejectLoosePerms(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "protonmail-mcp", "credentials.json")
	fs := NewFileStore(credPath)

	creds := &StoredCredentials{
		UID:           "uid-file-1",
		RefreshToken:  "ref-file-1",
		SaltedKeyPass: []byte("salted-pass-for-file"),
		Email:         "file@proton.me",
	}
	if err := fs.Save(creds); err != nil {
		t.Fatalf("FileStore.Save failed: %v", err)
	}

	// Verify directory is 0700 and file is 0600
	dirInfo, err := os.Stat(filepath.Dir(credPath))
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("expected directory mode 0700, got %#o", dirInfo.Mode().Perm())
	}
	fileInfo, err := os.Stat(credPath)
	if err != nil {
		t.Fatal(err)
	}
	if fileInfo.Mode().Perm() != 0600 {
		t.Fatalf("expected file mode 0600, got %#o", fileInfo.Mode().Perm())
	}

	// Load succeeds when 0600
	loaded, err := fs.Load()
	if err != nil {
		t.Fatalf("expected Load to succeed on 0600 file, got: %v", err)
	}
	if loaded.UID != "uid-file-1" || string(loaded.SaltedKeyPass) != "salted-pass-for-file" {
		t.Fatalf("unexpected loaded credentials: %+v", loaded)
	}
	loaded.Zero()

	// Loosen permissions to 0644 -> Load MUST reject with ErrInsecureFilePermissions
	if err := os.Chmod(credPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Load(); !errors.Is(err, ErrInsecureFilePermissions) {
		t.Fatalf("expected ErrInsecureFilePermissions for 0644 file, got: %v", err)
	}

	// Loosen permissions to 0660 -> Load MUST reject with ErrInsecureFilePermissions
	if err := os.Chmod(credPath, 0660); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Load(); !errors.Is(err, ErrInsecureFilePermissions) {
		t.Fatalf("expected ErrInsecureFilePermissions for 0660 file, got: %v", err)
	}

	// Restore 0600 -> Load succeeds again
	if err := os.Chmod(credPath, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Load(); err != nil {
		t.Fatalf("expected Load to succeed after restoring 0600, got: %v", err)
	}

	// Delete removes the file
	if err := fs.Delete(); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := fs.Load(); !errors.Is(err, ErrCredentialsNotFound) {
		t.Fatalf("expected ErrCredentialsNotFound after Delete, got: %v", err)
	}
}

func TestFallbackStore_OSKeychainPriorityAndHeadlessFileFallback(t *testing.T) {
	tmpDir := t.TempDir()
	credPath := filepath.Join(tmpDir, "credentials.json")

	// Case 1: OS Keychain works -> saves to Keychain, does not leave file on disk
	workingBackend := newMockKeyringBackend(nil)
	ksWorking := NewKeyringStore(workingBackend, "svc", "user")
	fsFallback := NewFileStore(credPath)
	chain := NewFallbackStore(ksWorking, fsFallback)

	creds := &StoredCredentials{
		UID:           "uid-kc",
		RefreshToken:  "ref-kc",
		SaltedKeyPass: []byte("keypass-kc"),
		Email:         "kc@proton.me",
	}
	if err := chain.Save(creds); err != nil {
		t.Fatalf("Save with working keychain failed: %v", err)
	}
	if chain.BackendName() != "os-keychain" {
		t.Fatalf("expected active backend 'os-keychain', got %q", chain.BackendName())
	}
	if _, err := os.Stat(credPath); !os.IsNotExist(err) {
		t.Fatal("expected fallback file not to exist when OS keychain succeeded")
	}

	// Case 2: OS Keychain unavailable (headless Linux) -> falls back to 0600 file
	failingBackend := newMockKeyringBackend(errors.New("dbus: session bus not available"))
	ksFailing := NewKeyringStore(failingBackend, "svc", "user")
	headlessChain := NewFallbackStore(ksFailing, fsFallback)

	credsFile := &StoredCredentials{
		UID:           "uid-headless",
		RefreshToken:  "ref-headless",
		SaltedKeyPass: []byte("keypass-headless"),
		Email:         "headless@proton.me",
	}
	if err := headlessChain.Save(credsFile); err != nil {
		t.Fatalf("Save with headless fallback failed: %v", err)
	}
	loaded, err := headlessChain.Load()
	if err != nil {
		t.Fatalf("Load from headless fallback failed: %v", err)
	}
	if loaded.UID != "uid-headless" || loaded.Email != "headless@proton.me" {
		t.Fatalf("unexpected loaded credentials: %+v", loaded)
	}

	// Delete wipes both primary and fallback
	if err := chain.Delete(); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}
	if _, err := headlessChain.Load(); !errors.Is(err, ErrCredentialsNotFound) {
		t.Fatalf("expected ErrCredentialsNotFound after Delete, got: %v", err)
	}
}
