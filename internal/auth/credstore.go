package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zalando/go-keyring"
)

const (
	DefaultKeyringService = "protonmail-mcp"
	DefaultKeyringAccount = "default-session"
	DefaultConfigDirName  = "protonmail-mcp"
	DefaultCredFileName   = "credentials.json"
)

var (
	ErrCredentialsNotFound     = errors.New("保存済みの認証情報が見つかりません")
	ErrInsecureFilePermissions = errors.New("認証情報ファイルのパーミッションが安全ではありません (0600 である必要があります)")
	ErrInvalidCredentials      = errors.New("認証情報の内容が不正または不完全です")
)

// StoredCredentials holds the tokens and derived PGP key passphrase required to
// restore a ProtonMail session and unlock PGP keys without storing the plaintext account password.
type StoredCredentials struct {
	UID           string    `json:"uid"`
	RefreshToken  string    `json:"refresh_token"`
	SaltedKeyPass []byte    `json:"salted_key_pass"`
	UserID        string    `json:"user_id,omitempty"`
	Email         string    `json:"email,omitempty"`
	DisplayName   string    `json:"display_name,omitempty"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Validate checks that required session and key-unlock fields are present.
func (c *StoredCredentials) Validate() error {
	if c == nil {
		return ErrInvalidCredentials
	}
	if strings.TrimSpace(c.UID) == "" || strings.TrimSpace(c.RefreshToken) == "" || len(c.SaltedKeyPass) == 0 {
		return ErrInvalidCredentials
	}
	return nil
}

// Zero overwrites sensitive byte slices in memory.
func (c *StoredCredentials) Zero() {
	if c == nil {
		return
	}
	ZeroBytes(c.SaltedKeyPass)
}

// Clone returns a deep copy of StoredCredentials so callers can safely Zero their copy.
func (c *StoredCredentials) Clone() *StoredCredentials {
	if c == nil {
		return nil
	}
	cp := *c
	if len(c.SaltedKeyPass) > 0 {
		cp.SaltedKeyPass = make([]byte, len(c.SaltedKeyPass))
		copy(cp.SaltedKeyPass, c.SaltedKeyPass)
	}
	return &cp
}

// CredentialStore abstracts persistent storage for session tokens and SaltedKeyPass.
type CredentialStore interface {
	Save(creds *StoredCredentials) error
	Load() (*StoredCredentials, error)
	Delete() error
	BackendName() string
}

// UpdateTokens updates UID and RefreshToken in the given store while preserving SaltedKeyPass.
func UpdateTokens(store CredentialStore, newUID, newRefreshToken string) error {
	if store == nil {
		return fmt.Errorf("credential store is nil")
	}
	if strings.TrimSpace(newRefreshToken) == "" {
		return ErrInvalidCredentials
	}
	creds, err := store.Load()
	if err != nil {
		return err
	}
	defer creds.Zero()

	if strings.TrimSpace(newUID) != "" {
		creds.UID = newUID
	}
	creds.RefreshToken = newRefreshToken
	creds.UpdatedAt = time.Now().UTC()
	return store.Save(creds)
}

// KeyringBackend abstracts OS keychain operations (e.g. zalando/go-keyring) for testability.
type KeyringBackend interface {
	Set(service, user, password string) error
	Get(service, user string) (string, error)
	Delete(service, user string) error
}

// OSKeyringBackend uses github.com/zalando/go-keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager).
type OSKeyringBackend struct{}

func (OSKeyringBackend) Set(service, user, password string) error {
	return keyring.Set(service, user, password)
}

func (OSKeyringBackend) Get(service, user string) (string, error) {
	return keyring.Get(service, user)
}

func (OSKeyringBackend) Delete(service, user string) error {
	return keyring.Delete(service, user)
}

// KeyringStore stores credentials in the OS keychain.
type KeyringStore struct {
	backend KeyringBackend
	service string
	account string
}

// NewKeyringStore creates a KeyringStore backed by the provided KeyringBackend.
func NewKeyringStore(backend KeyringBackend, service, account string) *KeyringStore {
	if backend == nil {
		backend = OSKeyringBackend{}
	}
	if service == "" {
		service = DefaultKeyringService
	}
	if account == "" {
		account = DefaultKeyringAccount
	}
	return &KeyringStore{
		backend: backend,
		service: service,
		account: account,
	}
}

func (ks *KeyringStore) BackendName() string {
	return "os-keychain"
}

func (ks *KeyringStore) Save(creds *StoredCredentials) error {
	if err := creds.Validate(); err != nil {
		return err
	}
	cp := creds.Clone()
	defer cp.Zero()
	if cp.UpdatedAt.IsZero() {
		cp.UpdatedAt = time.Now().UTC()
	}
	data, err := json.Marshal(cp)
	if err != nil {
		return fmt.Errorf("認証情報のシリアライズ失敗: %w", err)
	}
	defer ZeroBytes(data)

	if err := ks.backend.Set(ks.service, ks.account, string(data)); err != nil {
		return fmt.Errorf("OSキーチェーンへの保存失敗: %w", err)
	}
	return nil
}

func (ks *KeyringStore) Load() (*StoredCredentials, error) {
	raw, err := ks.backend.Get(ks.service, ks.account)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, ErrCredentialsNotFound
		}
		return nil, fmt.Errorf("%w: %v", ErrCredentialsNotFound, err)
	}
	var creds StoredCredentials
	if err := json.Unmarshal([]byte(raw), &creds); err != nil {
		return nil, fmt.Errorf("OSキーチェーン内の認証情報デコード失敗: %w", err)
	}
	if err := creds.Validate(); err != nil {
		creds.Zero()
		return nil, err
	}
	return &creds, nil
}

func (ks *KeyringStore) Delete() error {
	err := ks.backend.Delete(ks.service, ks.account)
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return err
	}
	return nil
}

// FileStore stores credentials in a 0600 permission-protected JSON file inside a 0700 directory.
type FileStore struct {
	mu   sync.Mutex
	path string
}

// DefaultCredFilePath returns the default credential file path (~/.config/protonmail-mcp/credentials.json
// or $PROTON_MCP_CRED_FILE if set).
func DefaultCredFilePath() (string, error) {
	if envPath := strings.TrimSpace(os.Getenv("PROTON_MCP_CRED_FILE")); envPath != "" {
		return filepath.Clean(envPath), nil
	}
	cfgDir, err := os.UserConfigDir()
	if err != nil || cfgDir == "" {
		home, herr := os.UserHomeDir()
		if herr != nil {
			return "", fmt.Errorf("ホームディレクトリの特定失敗: %w", herr)
		}
		cfgDir = filepath.Join(home, ".config")
	}
	return filepath.Join(cfgDir, DefaultConfigDirName, DefaultCredFileName), nil
}

// NewFileStore creates a FileStore at the given path.
func NewFileStore(path string) *FileStore {
	return &FileStore{path: filepath.Clean(path)}
}

func (fs *FileStore) Path() string {
	return fs.path
}

func (fs *FileStore) BackendName() string {
	return fmt.Sprintf("file (%s, mode 0600)", fs.path)
}

func (fs *FileStore) Save(creds *StoredCredentials) error {
	if err := creds.Validate(); err != nil {
		return err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()

	dir := filepath.Dir(fs.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("設定ディレクトリ作成失敗: %w", err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		return fmt.Errorf("設定ディレクトリ権限(0700)設定失敗: %w", err)
	}

	cp := creds.Clone()
	defer cp.Zero()
	if cp.UpdatedAt.IsZero() {
		cp.UpdatedAt = time.Now().UTC()
	}

	data, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		return fmt.Errorf("認証情報JSON変換失敗: %w", err)
	}
	defer ZeroBytes(data)

	tmpPath := fs.path + ".tmp"
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("一時ファイル作成失敗: %w", err)
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("ファイル権限(0600)設定失敗: %w", err)
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("認証情報書き込み失敗: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("ファイル同期失敗: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("ファイルクローズ失敗: %w", err)
	}
	if err := os.Rename(tmpPath, fs.path); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("認証情報ファイル配置失敗: %w", err)
	}
	return nil
}

func (fs *FileStore) Load() (*StoredCredentials, error) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	fi, err := os.Lstat(fs.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrCredentialsNotFound
		}
		return nil, fmt.Errorf("認証情報ファイル確認失敗: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: 通常ファイルではありません", ErrInsecureFilePermissions)
	}
	// 0600 厳格チェック: グループまたは他者への権限ビット (0077) が1つでも立っていれば拒否
	if perm := fi.Mode().Perm(); perm&0077 != 0 {
		return nil, fmt.Errorf("%w: 現在の権限=%#o (%s)", ErrInsecureFilePermissions, perm, fs.path)
	}

	data, err := os.ReadFile(fs.path)
	if err != nil {
		return nil, fmt.Errorf("認証情報ファイル読み込み失敗: %w", err)
	}
	defer ZeroBytes(data)

	var creds StoredCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("認証情報ファイルデコード失敗: %w", err)
	}
	if err := creds.Validate(); err != nil {
		creds.Zero()
		return nil, err
	}
	return &creds, nil
}

func (fs *FileStore) Delete() error {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	if err := os.Remove(fs.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("認証情報ファイル削除失敗: %w", err)
	}
	return nil
}

// FallbackStore tries Primary (OS Keychain) first and automatically falls back to
// Fallback (0600 permission-protected file) when the OS keychain is unavailable
// (e.g. headless Linux servers without D-Bus Secret Service).
type FallbackStore struct {
	mu         sync.RWMutex
	primary    CredentialStore
	fallback   CredentialStore
	activeName string
}

// NewFallbackStore creates a FallbackStore with the given primary and fallback stores.
func NewFallbackStore(primary, fallback CredentialStore) *FallbackStore {
	name := "os-keychain"
	if primary != nil {
		name = primary.BackendName()
	}
	return &FallbackStore{
		primary:    primary,
		fallback:   fallback,
		activeName: name,
	}
}

// NewDefaultCredentialStore constructs the standard OS Keychain + ~/.config/protonmail-mcp/credentials.json fallback store.
func NewDefaultCredentialStore() CredentialStore {
	ks := NewKeyringStore(OSKeyringBackend{}, DefaultKeyringService, DefaultKeyringAccount)
	path, err := DefaultCredFilePath()
	if err != nil {
		return ks
	}
	fs := NewFileStore(path)
	return NewFallbackStore(ks, fs)
}

func (s *FallbackStore) BackendName() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.activeName
}

func (s *FallbackStore) Save(creds *StoredCredentials) error {
	if s.primary != nil {
		if err := s.primary.Save(creds); err == nil {
			if s.fallback != nil {
				_ = s.fallback.Delete()
			}
			s.mu.Lock()
			s.activeName = s.primary.BackendName()
			s.mu.Unlock()
			return nil
		}
	}
	if s.fallback == nil {
		return fmt.Errorf("利用可能な認証情報ストアがありません")
	}
	if err := s.fallback.Save(creds); err != nil {
		return err
	}
	s.mu.Lock()
	s.activeName = s.fallback.BackendName()
	s.mu.Unlock()
	return nil
}

func (s *FallbackStore) Load() (*StoredCredentials, error) {
	if s.primary != nil {
		creds, err := s.primary.Load()
		if err == nil {
			s.mu.Lock()
			s.activeName = s.primary.BackendName()
			s.mu.Unlock()
			return creds, nil
		}
	}
	if s.fallback != nil {
		creds, err := s.fallback.Load()
		if err == nil {
			s.mu.Lock()
			s.activeName = s.fallback.BackendName()
			s.mu.Unlock()
			return creds, nil
		}
		return nil, err
	}
	return nil, ErrCredentialsNotFound
}

func (s *FallbackStore) Delete() error {
	var firstErr error
	if s.primary != nil {
		if err := s.primary.Delete(); err != nil && !errors.Is(err, ErrCredentialsNotFound) {
			firstErr = err
		}
	}
	if s.fallback != nil {
		if err := s.fallback.Delete(); err != nil && !errors.Is(err, ErrCredentialsNotFound) && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// MemoryStore is a thread-safe in-memory CredentialStore used for unit tests.
type MemoryStore struct {
	mu    sync.RWMutex
	creds *StoredCredentials
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{}
}

func (m *MemoryStore) BackendName() string {
	return "memory"
}

func (m *MemoryStore) Save(creds *StoredCredentials) error {
	if err := creds.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.creds != nil {
		m.creds.Zero()
	}
	cp := creds.Clone()
	if cp.UpdatedAt.IsZero() {
		cp.UpdatedAt = time.Now().UTC()
	}
	m.creds = cp
	return nil
}

func (m *MemoryStore) Load() (*StoredCredentials, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.creds == nil {
		return nil, ErrCredentialsNotFound
	}
	return m.creds.Clone(), nil
}

func (m *MemoryStore) Delete() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.creds != nil {
		m.creds.Zero()
		m.creds = nil
	}
	return nil
}
