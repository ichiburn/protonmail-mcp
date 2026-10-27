package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/gluon/rfc822"
	proton "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/ichiburn/protonmail-mcp/internal/auth"
	mailpkg "github.com/ichiburn/protonmail-mcp/internal/mail"
	mcppkg "github.com/ichiburn/protonmail-mcp/internal/mcp"
	"github.com/ichiburn/protonmail-mcp/internal/security"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"golang.org/x/term"
)

// session はログインセッションの状態を保持する。
// sessionMu で保護し、refcount で使用中のハンドラがある間は Close されない。
type session struct {
	client  *proton.Client
	mgr     *proton.Manager
	userKR  *crypto.KeyRing
	addrKRs map[string]*crypto.KeyRing
	addr    *mail.Address
	addrID  string
	refs    sync.WaitGroup
	closed  bool
}

// ProtonBackend abstracts Proton API authentication and session restoration operations
// so that CLI login/status/logout and MCP keychain restoration can be unit-tested deterministically.
type ProtonBackend interface {
	LoginAndDerive(ctx context.Context, username string, passBytes []byte, prompt2FA func() (string, error)) (*auth.StoredCredentials, error)
	RestoreSession(ctx context.Context, creds *auth.StoredCredentials, onAuthRefresh func(uid, refreshToken string)) (*session, string, string, error)
	RevokeSession(ctx context.Context, creds *auth.StoredCredentials) error
}

var (
	sessionMu sync.RWMutex
	sess      *session

	// OSキーチェーン優先＋0600ファイルフォールバックの認証情報ストア
	credStore auth.CredentialStore = auth.NewDefaultCredentialStore()

	// Proton API 認証バックエンド
	protonBackend ProtonBackend = &defaultProtonBackend{hostURL: "https://mail.proton.me/api"}

	// 送信レート制限（10分あたり5通）
	rateLimiter = security.NewRateLimiter(maxSendsPerWindow, sendWindow)

	// 送信確認トークン管理（5分有効・最大50件）
	tokenStore = security.NewTokenStore(tokenExpiry, maxPendingSends)
)

const (
	// appName / appVersion はツールの正直な自己申告。x-pm-appversion ヘッダ（AppVersion）と
	// MCPサーバー宣言の両方で使い、二重管理を避ける（Single Source of Truth）。
	// 公式クライアント（web-mail 等）を偽装せず、go-proton-api ベースの非公式ツールだと名乗る。
	appName    = "protonmail-mcp"
	appVersion = "0.1.0"

	maxSendsPerWindow  = security.MaxSendsPerWindow
	sendWindow         = security.SendWindow
	tokenExpiry        = security.TokenExpiry
	maxPendingSends    = security.MaxPendingSends
	maxLimit           = security.MaxLimit
	maxAttachmentSize  = security.MaxAttachmentSize
	maxTotalAttSize    = security.MaxTotalAttSize
	maxAttachmentCount = security.MaxAttachmentCount
)

var messageIDPattern = security.MessageIDPattern

func main() {
	if len(os.Args) > 1 {
		code := runCLI(context.Background(), os.Args[1:], os.Stdin, os.Stdout, os.Stderr)
		os.Exit(code)
	}

	// MCPサーバー起動時に保存済みセッション（OSキーチェーン / 0600ファイル）があれば自動復元を試みる
	_ = tryAutoRestoreSession(context.Background())

	s := server.NewMCPServer(
		appName,
		appVersion,
		server.WithToolCapabilities(true),
	)

	s.AddTool(mcp.NewTool("protonmail_login",
		mcp.WithDescription("ProtonMailにログインする。OSキーチェーン（事前に `protonmail-mcp login` で保存したセッション）から自動復元するか、未保存の場合はサーバープロセスの環境変数（PROTON_USER / PROTON_PASS、2FA有効時は PROTON_TOTP_SECRET）から読み込む。セキュリティ上、ツール引数では認証情報を受け付けない。"),
	), loginHandler)

	s.AddTool(mcp.NewTool("protonmail_list_messages",
		mcp.WithDescription("メール一覧を取得する。フォルダやキーワードでフィルタ可能。"),
		mcp.WithString("folder", mcp.Description("フォルダ: inbox, sent, drafts, trash, spam, archive, all (デフォルト: inbox)")),
		mcp.WithString("subject", mcp.Description("件名フィルタ")),
		mcp.WithNumber("limit", mcp.Description("取得件数 (デフォルト: 20, 最大: 150)")),
		mcp.WithNumber("page", mcp.Description("ページ番号 (デフォルト: 0)")),
	), listMessagesHandler)

	s.AddTool(mcp.NewTool("protonmail_read_message",
		mcp.WithDescription("メールの本文を復号して読む。"),
		mcp.WithString("message_id", mcp.Required(), mcp.Description("メッセージID")),
	), readMessageHandler)

	s.AddTool(mcp.NewTool("protonmail_search_messages",
		mcp.WithDescription("送信者やキーワードでメールを検索する。"),
		mcp.WithString("sender", mcp.Description("送信者メールアドレス（部分一致）")),
		mcp.WithString("subject", mcp.Description("件名キーワード")),
		mcp.WithString("keyword", mcp.Description("本文キーワード（件名で部分一致フィルタ）")),
		mcp.WithNumber("limit", mcp.Description("取得件数 (デフォルト: 20, 最大: 150)")),
	), searchMessagesHandler)

	s.AddTool(mcp.NewTool("protonmail_send_preview",
		mcp.WithDescription("メール送信のプレビューを生成する。実際には送信されない。確認トークンが返されるので、ユーザーの明示的な承認後に protonmail_send_confirm で送信すること。"),
		mcp.WithString("to", mcp.Required(), mcp.Description("宛先メールアドレス（カンマ区切りで複数可）")),
		mcp.WithString("subject", mcp.Required(), mcp.Description("件名")),
		mcp.WithString("body", mcp.Required(), mcp.Description("本文（プレーンテキスト）")),
		mcp.WithString("cc", mcp.Description("CCメールアドレス（カンマ区切り）")),
		mcp.WithString("attachments", mcp.Description("添付ファイルパス（カンマ区切りで複数可）")),
	), sendPreviewHandler)

	s.AddTool(mcp.NewTool("protonmail_send_confirm",
		mcp.WithDescription("プレビュー済みメールを実際に送信する。protonmail_send_preview で取得した confirm_token が必須。トークンは5分間有効。"),
		mcp.WithString("confirm_token", mcp.Required(), mcp.Description("protonmail_send_preview で発行された確認トークン")),
	), sendConfirmHandler)

	if err := server.ServeStdio(s); err != nil {
		log.Fatal(err)
	}
}

// --- CLI Subcommands (login / status / logout) ---

func runCLI(ctx context.Context, args []string, in io.Reader, out, errOut io.Writer) int {
	if len(args) == 0 {
		return 0
	}
	cmd := strings.ToLower(strings.TrimSpace(args[0]))
	switch cmd {
	case "login":
		if err := runCLILogin(ctx, in, out); err != nil {
			fmt.Fprintf(errOut, "Error: %v\n", err)
			return 1
		}
		return 0
	case "status":
		offline := false
		for _, a := range args[1:] {
			if a == "--offline" {
				offline = true
			}
		}
		if err := runCLIStatus(ctx, offline, out); err != nil {
			fmt.Fprintf(errOut, "Status: %v\n", err)
			return 1
		}
		return 0
	case "logout":
		if err := runCLILogout(ctx, out); err != nil {
			fmt.Fprintf(errOut, "Error: %v\n", err)
			return 1
		}
		return 0
	case "version", "--version", "-v":
		fmt.Fprintf(out, "%s@%s\n", appName, appVersion)
		return 0
	case "help", "--help", "-h":
		printCLIUsage(out)
		return 0
	default:
		fmt.Fprintf(errOut, "Unknown command: %s\n\n", args[0])
		printCLIUsage(errOut)
		return 2
	}
}

func printCLIUsage(w io.Writer) {
	fmt.Fprintf(w, `%s (%s) — ProtonMail MCP Server

Usage:
  %s            Start MCP server over stdio (restores session from OS keychain if logged in)
  %s login      Authenticate interactively once and store session token + key passphrase in OS keychain
  %s status     Check stored session status (use --offline to skip live API check)
  %s logout     Revoke session and delete stored credentials from OS keychain and local fallback
  %s version    Print version
`, appName, appVersion, appName, appName, appName, appName, appName)
}

func readSecretLine(reader *bufio.Reader, in io.Reader) ([]byte, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		b, err := term.ReadPassword(int(f.Fd()))
		return b, err
	}
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	line = strings.TrimRight(line, "\r\n")
	return []byte(line), nil
}

func runCLILogin(ctx context.Context, in io.Reader, out io.Writer) error {
	reader := bufio.NewReader(in)

	fmt.Fprint(out, "ProtonMail Email: ")
	emailLine, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("メールアドレス入力の読み取り失敗: %w", err)
	}
	username := strings.TrimSpace(emailLine)
	if username == "" {
		return fmt.Errorf("メールアドレスが空です")
	}

	fmt.Fprint(out, "Password: ")
	passBytes, err := readSecretLine(reader, in)
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprintln(out)
	}
	if err != nil {
		auth.ZeroBytes(passBytes)
		return fmt.Errorf("パスワード入力の読み取り失敗: %w", err)
	}
	defer auth.ZeroBytes(passBytes)
	if len(passBytes) == 0 {
		return fmt.Errorf("パスワードが空です")
	}

	prompt2FA := func() (string, error) {
		fmt.Fprint(out, "2FA TOTP Code (6 digits) or Base32 Secret: ")
		rawBytes, err := readSecretLine(reader, in)
		if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			fmt.Fprintln(out)
		}
		if err != nil {
			auth.ZeroBytes(rawBytes)
			return "", fmt.Errorf("2FA入力の読み取り失敗: %w", err)
		}
		defer auth.ZeroBytes(rawBytes)
		return auth.ResolveTOTPInput(string(rawBytes), time.Now())
	}

	creds, err := protonBackend.LoginAndDerive(ctx, username, passBytes, prompt2FA)
	if err != nil {
		return err
	}
	defer creds.Zero()

	if err := credStore.Save(creds); err != nil {
		return fmt.Errorf("認証情報の保存失敗: %w", err)
	}

	fmt.Fprintf(out, "ログイン成功: %s (%s)\n", creds.DisplayName, creds.Email)
	fmt.Fprintf(out, "保存先: %s\n", credStore.BackendName())
	fmt.Fprintln(out, "完了: .mcp.json に PROTON_USER / PROTON_PASS を記載せずに MCP サーバーを起動できます。")
	return nil
}

func runCLIStatus(ctx context.Context, offline bool, out io.Writer) error {
	creds, err := credStore.Load()
	if err != nil {
		return fmt.Errorf("未ログイン (%v)。先に `protonmail-mcp login` を実行してください", err)
	}
	defer creds.Zero()

	fmt.Fprintf(out, "Status: Stored credentials found\n")
	fmt.Fprintf(out, "Backend: %s\n", credStore.BackendName())
	if creds.DisplayName != "" {
		fmt.Fprintf(out, "Account: %s <%s>\n", creds.DisplayName, creds.Email)
	} else {
		fmt.Fprintf(out, "Account: %s\n", creds.Email)
	}
	if !creds.UpdatedAt.IsZero() {
		fmt.Fprintf(out, "Updated: %s\n", creds.UpdatedAt.Format(time.RFC3339))
	}

	if offline {
		fmt.Fprintln(out, "Session verification: skipped (--offline)")
		return nil
	}

	s, newUID, newRef, err := protonBackend.RestoreSession(ctx, creds, makeTokenRotationCallback())
	if err != nil {
		return fmt.Errorf("保存済みセッションの有効性確認に失敗しました（再ログインが必要です）: %w", err)
	}
	if newRef != "" {
		_ = auth.UpdateTokens(credStore, newUID, newRef)
	}
	if s.client != nil {
		s.client.Close()
	}
	if s.mgr != nil {
		s.mgr.Close()
	}
	fmt.Fprintln(out, "Session verification: active (RefreshToken & PGP keyring unlock verified)")
	return nil
}

func runCLILogout(ctx context.Context, out io.Writer) error {
	if creds, err := credStore.Load(); err == nil {
		_ = protonBackend.RevokeSession(ctx, creds)
		creds.Zero()
	}
	if err := credStore.Delete(); err != nil {
		return fmt.Errorf("保存済み認証情報の削除失敗: %w", err)
	}
	sessionMu.Lock()
	closeSession()
	sessionMu.Unlock()

	fmt.Fprintln(out, "ログアウト完了: OSキーチェーンおよびローカル保存先の認証情報を消去しました。")
	return nil
}

// --- Default ProtonBackend Implementation ---

type defaultProtonBackend struct {
	hostURL string
}

func (b *defaultProtonBackend) newManager() *proton.Manager {
	return proton.New(
		proton.WithHostURL(b.hostURL),
		proton.WithAppVersion(appName+"@"+appVersion),
	)
}

func (b *defaultProtonBackend) LoginAndDerive(
	ctx context.Context,
	username string,
	passBytes []byte,
	prompt2FA func() (string, error),
) (*auth.StoredCredentials, error) {
	defer auth.ZeroBytes(passBytes)

	mgr := b.newManager()
	defer mgr.Close()

	c, pAuth, err := mgr.NewClientWithLogin(ctx, username, passBytes)
	if err != nil {
		return nil, fmt.Errorf("ログイン失敗。認証情報、またはProton側のアカウント制限を確認してください")
	}
	defer c.Close()

	if pAuth.TwoFA.Enabled&proton.HasTOTP != 0 {
		if prompt2FA == nil {
			return nil, fmt.Errorf("2FAが有効ですが2FA入力プロバイダが未設定です")
		}
		code, err := prompt2FA()
		if err != nil {
			return nil, fmt.Errorf("TOTPコード取得失敗: %w", err)
		}
		if err := c.Auth2FA(ctx, proton.Auth2FAReq{TwoFactorCode: code}); err != nil {
			return nil, fmt.Errorf("2FA認証失敗: %w", err)
		}
	}

	user, err := c.GetUser(ctx)
	if err != nil {
		return nil, fmt.Errorf("ユーザー情報取得失敗: %w", err)
	}

	salts, err := c.GetSalts(ctx)
	if err != nil {
		return nil, fmt.Errorf("Salt取得失敗: %w", err)
	}

	addrs, err := c.GetAddresses(ctx)
	if err != nil {
		return nil, fmt.Errorf("アドレス取得失敗: %w", err)
	}

	saltedKeyPass, err := salts.SaltForKey(passBytes, user.Keys.Primary().ID)
	if err != nil {
		return nil, fmt.Errorf("鍵パスフレーズ導出失敗: %w", err)
	}
	defer auth.ZeroBytes(saltedKeyPass)

	if _, _, err := proton.Unlock(user, addrs, saltedKeyPass); err != nil {
		return nil, fmt.Errorf("キーリングアンロック検証失敗: %w", err)
	}

	email := user.Email
	if len(addrs) > 0 && addrs[0].Email != "" {
		email = addrs[0].Email
	}

	keyPassCopy := make([]byte, len(saltedKeyPass))
	copy(keyPassCopy, saltedKeyPass)

	return &auth.StoredCredentials{
		UID:           pAuth.UID,
		RefreshToken:  pAuth.RefreshToken,
		SaltedKeyPass: keyPassCopy,
		UserID:        user.ID,
		Email:         email,
		DisplayName:   user.Name,
		UpdatedAt:     time.Now().UTC(),
	}, nil
}

func (b *defaultProtonBackend) RestoreSession(
	ctx context.Context,
	creds *auth.StoredCredentials,
	onAuthRefresh func(uid, refreshToken string),
) (*session, string, string, error) {
	if err := creds.Validate(); err != nil {
		return nil, "", "", err
	}
	keyPass := make([]byte, len(creds.SaltedKeyPass))
	copy(keyPass, creds.SaltedKeyPass)
	defer auth.ZeroBytes(keyPass)

	mgr := b.newManager()
	success := false
	defer func() {
		if !success {
			mgr.Close()
		}
	}()

	c, pAuth, err := mgr.NewClientWithRefresh(ctx, creds.UID, creds.RefreshToken)
	if err != nil {
		return nil, "", "", fmt.Errorf("トークンリフレッシュ失敗: %w", err)
	}
	defer func() {
		if !success {
			c.Close()
		}
	}()

	if onAuthRefresh != nil {
		c.AddAuthHandler(func(rotated proton.Auth) {
			onAuthRefresh(rotated.UID, rotated.RefreshToken)
		})
	}

	user, err := c.GetUser(ctx)
	if err != nil {
		return nil, "", "", fmt.Errorf("ユーザー情報取得失敗: %w", err)
	}

	addrs, err := c.GetAddresses(ctx)
	if err != nil {
		return nil, "", "", fmt.Errorf("アドレス取得失敗: %w", err)
	}

	ukr, akrs, err := proton.Unlock(user, addrs, keyPass)
	if err != nil {
		return nil, "", "", fmt.Errorf("キーリングアンロック失敗: %w", err)
	}

	var sAddr *mail.Address
	var sAddrID string
	if len(addrs) > 0 {
		sAddr = &mail.Address{Name: user.Name, Address: addrs[0].Email}
		sAddrID = addrs[0].ID
	} else {
		sAddr = &mail.Address{Name: user.Name, Address: user.Email}
	}

	s := &session{
		client:  c,
		mgr:     mgr,
		userKR:  ukr,
		addrKRs: akrs,
		addr:    sAddr,
		addrID:  sAddrID,
	}
	success = true
	return s, pAuth.UID, pAuth.RefreshToken, nil
}

func (b *defaultProtonBackend) RevokeSession(ctx context.Context, creds *auth.StoredCredentials) error {
	if creds == nil || creds.UID == "" || creds.RefreshToken == "" {
		return nil
	}
	mgr := b.newManager()
	defer mgr.Close()

	c, _, err := mgr.NewClientWithRefresh(ctx, creds.UID, creds.RefreshToken)
	if err != nil {
		return err
	}
	defer c.Close()
	return c.AuthDelete(ctx)
}

func makeTokenRotationCallback() func(uid, refreshToken string) {
	return func(uid, refreshToken string) {
		if refreshToken == "" {
			return
		}
		if err := auth.UpdateTokens(credStore, uid, refreshToken); err != nil {
			log.Printf("warning: failed to persist rotated auth token: %v", err)
		}
	}
}

func tryAutoRestoreSession(ctx context.Context) error {
	creds, err := credStore.Load()
	if err != nil {
		return err
	}
	defer creds.Zero()

	s, newUID, newRef, err := protonBackend.RestoreSession(ctx, creds, makeTokenRotationCallback())
	if err != nil {
		return err
	}
	if newRef != "" {
		_ = auth.UpdateTokens(credStore, newUID, newRef)
	}

	sessionMu.Lock()
	closeSession()
	sess = s
	sessionMu.Unlock()
	return nil
}

// acquireSession はセッションを安全に取得し、参照カウントを増やす。
// メモリ上にセッションが無い場合、OSキーチェーン/保存済み認証情報があれば自動復元を試みる。
// 使用後は必ず releaseSession を呼ぶこと。
func acquireSession() (*session, error) {
	sessionMu.RLock()
	s := sess
	if s != nil && !s.closed {
		s.refs.Add(1)
	} else {
		s = nil
	}
	sessionMu.RUnlock()
	if s != nil {
		return s, nil
	}

	// 保存済み認証情報があれば自動復元を試行
	if err := tryAutoRestoreSession(context.Background()); err == nil {
		sessionMu.RLock()
		s = sess
		if s != nil && !s.closed {
			s.refs.Add(1)
		} else {
			s = nil
		}
		sessionMu.RUnlock()
		if s != nil {
			return s, nil
		}
	}

	return nil, fmt.Errorf("未ログインです。先に `protonmail-mcp login`（CLI）または protonmail_login ツールを実行してください。")
}

// releaseSession は参照カウントを減らす。
func releaseSession(s *session) {
	s.refs.Done()
}

// closeSession は既存セッションを安全にクローズする。sessionMu.Lock() を保持して呼ぶこと。
// acquireSession は RLock を使うため、ここで Wait() してもデッドロックしない。
// N-R7-3対策: ハンドラがハングした場合に備えてタイムアウトを設ける。
func closeSession() {
	if sess != nil {
		old := sess
		old.closed = true
		sess = nil

		// タイムアウト付きでハンドラの完了を待つ
		done := make(chan struct{})
		go func() {
			old.refs.Wait()
			close(done)
		}()

		select {
		case <-done:
			// 全ハンドラが正常に完了
		case <-time.After(30 * time.Second):
			// タイムアウト: ハンドラがハングしている可能性。強制的にクローズを続行。
			log.Println("warning: closeSession timed out waiting for handlers, forcing close")
		}

		if old.client != nil {
			old.client.Close()
		}
		if old.mgr != nil {
			old.mgr.Close()
		}
	}
}

func loginHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	// 1. OSキーチェーン / 保存済み認証情報からのセッション復元を最優先で試行（環境変数不要）
	if creds, err := credStore.Load(); err == nil {
		defer creds.Zero()
		s, newUID, newRef, rerr := protonBackend.RestoreSession(ctx, creds, makeTokenRotationCallback())
		if rerr == nil {
			if newRef != "" {
				_ = auth.UpdateTokens(credStore, newUID, newRef)
			}
			sessionMu.Lock()
			closeSession()
			sess = s
			sessionMu.Unlock()

			addrStr := formatMailAddress(s.addr)
			return mcp.NewToolResultText(fmt.Sprintf("ログイン成功 (保存済みセッションから復元 [%s]): %s", credStore.BackendName(), addrStr)), nil
		}
		// 保存済みセッションが失効しており、かつ環境変数も無い場合はエラーを返す
		if os.Getenv("PROTON_USER") == "" || os.Getenv("PROTON_PASS") == "" {
			return mcp.NewToolResultError(fmt.Sprintf("保存済みセッションの復元に失敗しました (%v)。ターミナルで `protonmail-mcp login` を再実行してください。", rerr)), nil
		}
	}

	// 2. 後方互換フォールバック: 環境変数（PROTON_USER / PROTON_PASS）からのログイン
	username := os.Getenv("PROTON_USER")
	passStr := os.Getenv("PROTON_PASS")
	if username == "" || passStr == "" {
		return mcp.NewToolResultError("認証情報が未設定です。ターミナルで `protonmail-mcp login` を実行してOSキーチェーンに保存するか、サーバープロセスの環境変数 PROTON_USER と PROTON_PASS を設定してください。"), nil
	}

	// N5対策: パスワードをできるだけ早く[]byteに変換し、使用後にゼロ埋め
	passBytes := []byte(passStr)
	defer auth.ZeroBytes(passBytes)

	mgr := proton.New(
		proton.WithHostURL("https://mail.proton.me/api"),
		// 公式クライアントを偽装せず、ツールを正直に名乗る（name@version 形式）。
		proton.WithAppVersion(appName+"@"+appVersion),
	)

	// N13対策: ログイン成功するまで mgr と c を defer でクリーンアップ
	loginSuccess := false
	defer func() {
		if !loginSuccess {
			mgr.Close()
		}
	}()

	c, pAuth, err := mgr.NewClientWithLogin(ctx, username, passBytes)
	if err != nil {
		return mcp.NewToolResultError("ログイン失敗。認証情報、またはProton側のアカウント制限（一時的なアクセス制限など）を確認してください。"), nil
	}
	defer func() {
		if !loginSuccess {
			c.Close()
		}
	}()

	if pAuth.TwoFA.Enabled&proton.HasTOTP != 0 {
		totpSeed := os.Getenv("PROTON_TOTP_SECRET")
		if totpSeed == "" {
			return mcp.NewToolResultError("2FAが有効ですが PROTON_TOTP_SECRET が未設定です。Base32形式のTOTPシードを環境変数に設定してください。"), nil
		}
		code, err := generateTOTPCode(totpSeed, time.Now())
		if err != nil {
			return mcp.NewToolResultError("TOTPコード生成失敗。PROTON_TOTP_SECRET の形式（Base32）を確認してください。"), nil
		}
		if err := c.Auth2FA(ctx, proton.Auth2FAReq{TwoFactorCode: code}); err != nil {
			return mcp.NewToolResultError("2FA認証失敗。PROTON_TOTP_SECRET を確認してください。"), nil
		}
	}

	user, err := c.GetUser(ctx)
	if err != nil {
		return mcp.NewToolResultError("ユーザー情報取得失敗。再試行してください。"), nil
	}

	salts, err := c.GetSalts(ctx)
	if err != nil {
		return mcp.NewToolResultError("Salt取得失敗。再試行してください。"), nil
	}

	addrs, err := c.GetAddresses(ctx)
	if err != nil {
		return mcp.NewToolResultError("アドレス取得失敗。再試行してください。"), nil
	}

	saltedKeyPass, err := salts.SaltForKey(passBytes, user.Keys.Primary().ID)
	if err != nil {
		return mcp.NewToolResultError("鍵パスフレーズ導出失敗。再試行してください。"), nil
	}

	ukr, akrs, err := proton.Unlock(user, addrs, saltedKeyPass)

	// C2対策: saltedKeyPassを即座にゼロ埋め
	auth.ZeroBytes(saltedKeyPass)

	if err != nil {
		return mcp.NewToolResultError("キーリングアンロック失敗。再試行してください。"), nil
	}

	var sAddr *mail.Address
	var sAddrID string
	if len(addrs) > 0 {
		sAddr = &mail.Address{Name: user.Name, Address: addrs[0].Email}
		sAddrID = addrs[0].ID
	}

	// N1+N4対策: 既存セッションをクローズしてから新セッションを設定
	sessionMu.Lock()
	closeSession()
	sess = &session{
		client:  c,
		mgr:     mgr,
		userKR:  ukr,
		addrKRs: akrs,
		addr:    sAddr,
		addrID:  sAddrID,
	}
	loginSuccess = true // defer でのクリーンアップを抑制
	sessionMu.Unlock()

	return mcp.NewToolResultText(fmt.Sprintf("ログイン成功: %s (%s)", user.Name, user.Email)), nil
}

func listMessagesHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s, err := acquireSession()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer releaseSession(s)

	folder := stringArg(req, "folder")
	if folder == "" {
		folder = "inbox"
	}
	subject := stringArg(req, "subject")
	limit := clampInt(intArg(req, "limit", 20), 1, maxLimit)
	page := clampInt(intArg(req, "page", 0), 0, 1000)

	filter := proton.MessageFilter{
		LabelID: folderToLabel(folder),
	}
	if subject != "" {
		filter.Subject = subject
	}

	msgs, err := s.client.GetMessageMetadataPage(ctx, page, limit, filter)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("メール取得失敗: %v", err)), nil
	}

	results := make([]map[string]interface{}, 0, len(msgs))
	for _, m := range msgs {
		results = append(results, map[string]interface{}{
			"id":      m.ID,
			"subject": m.Subject,
			"sender":  formatMailAddress(m.Sender),
			"to":      formatMailAddresses(m.ToList),
			"date":    time.Unix(m.Time, 0).Format("2006-01-02 15:04"),
			"unread":  bool(m.Unread),
		})
	}

	out, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("JSON変換失敗: %v", err)), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}

func readMessageHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s, err := acquireSession()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer releaseSession(s)

	msgID := stringArg(req, "message_id")
	if msgID == "" {
		return mcp.NewToolResultError("message_id は必須です。"), nil
	}

	// N6対策: message_idのフォーマット検証
	if !security.ValidateMessageID(msgID) {
		return mcp.NewToolResultError("不正なメッセージIDフォーマットです。"), nil
	}

	msg, err := s.client.GetMessage(ctx, msgID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("メッセージ取得失敗: %v", err)), nil
	}

	kr, ok := s.addrKRs[msg.AddressID]
	if !ok {
		return mcp.NewToolResultError("このメッセージのアドレスに対応するキーリングがありません。"), nil
	}

	decrypted, err := msg.Decrypt(kr)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("復号失敗: %v", err)), nil
	}

	sanitizedBody := sanitizeEmailBody(string(decrypted))

	result := map[string]interface{}{
		"id":       msg.ID,
		"subject":  msg.Subject,
		"sender":   formatMailAddress(msg.Sender),
		"to":       formatMailAddresses(msg.ToList),
		"cc":       formatMailAddresses(msg.CCList),
		"date":     time.Unix(msg.Time, 0).Format("2006-01-02 15:04"),
		"body":     sanitizedBody,
		"_warning": security.UntrustedWarning,
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("JSON変換失敗: %v", err)), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}

func searchMessagesHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s, err := acquireSession()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer releaseSession(s)

	senderFilter := strings.ToLower(stringArg(req, "sender"))
	subject := stringArg(req, "subject")
	keyword := strings.ToLower(stringArg(req, "keyword"))
	limit := clampInt(intArg(req, "limit", 20), 1, maxLimit)

	filter := proton.MessageFilter{
		LabelID: proton.AllMailLabel,
	}
	if subject != "" {
		filter.Subject = subject
	}

	fetchLimit := clampInt(limit*3, 50, maxLimit*2)

	msgs, err := s.client.GetMessageMetadataPage(ctx, 0, fetchLimit, filter)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("検索失敗: %v", err)), nil
	}

	results := make([]map[string]interface{}, 0)
	for _, m := range msgs {
		if senderFilter != "" {
			addr := strings.ToLower(m.Sender.Address)
			name := strings.ToLower(m.Sender.Name)
			if !strings.Contains(addr, senderFilter) && !strings.Contains(name, senderFilter) {
				continue
			}
		}

		if keyword != "" {
			if !strings.Contains(strings.ToLower(m.Subject), keyword) {
				continue
			}
		}

		results = append(results, map[string]interface{}{
			"id":      m.ID,
			"subject": m.Subject,
			"sender":  formatMailAddress(m.Sender),
			"date":    time.Unix(m.Time, 0).Format("2006-01-02 15:04"),
			"unread":  bool(m.Unread),
		})
		if len(results) >= limit {
			break
		}
	}

	out, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("JSON変換失敗: %v", err)), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}

func sendPreviewHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s, err := acquireSession()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer releaseSession(s)
	if s.addr == nil {
		return mcp.NewToolResultError("送信者アドレスが未設定です。再ログインしてください。"), nil
	}

	to := stringArg(req, "to")
	subject := stringArg(req, "subject")
	body := stringArg(req, "body")
	cc := stringArg(req, "cc")
	attachmentsStr := stringArg(req, "attachments")

	if to == "" || subject == "" || body == "" {
		return mcp.NewToolResultError("to, subject, body は必須です。"), nil
	}

	// 添付ファイルの検証
	var attachments []string
	if attachmentsStr != "" {
		parts := strings.Split(attachmentsStr, ",")
		if len(parts) > maxAttachmentCount {
			return mcp.NewToolResultError(fmt.Sprintf("添付ファイル数が上限（%d個）を超えています。", maxAttachmentCount)), nil
		}
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			validPath, err := validateAttachmentPath(p)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("添付ファイルエラー: %s: %v", p, err)), nil
			}
			attachments = append(attachments, validPath)
		}
	}

	// N3対策: pending上限チェックと256-bitトークン発行
	token, err := tokenStore.Create(security.PendingSend{
		To:          to,
		CC:          cc,
		Subject:     subject,
		Body:        body,
		Attachments: attachments,
	})
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	preview := map[string]interface{}{
		"mode":          "プレビュー（未送信）",
		"from":          formatMailAddress(s.addr),
		"to":            to,
		"cc":            cc,
		"subject":       subject,
		"body":          body,
		"attachments":   attachments,
		"confirm_token": token,
		"expires_in":    fmt.Sprintf("%d分", int(tokenExpiry.Minutes())),
		"_notice":       "これはプレビューです。実際に送信するには、ユーザーの承認を得た上で protonmail_send_confirm に confirm_token を渡してください。",
	}
	out, err := json.MarshalIndent(preview, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("JSON変換失敗: %v", err)), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}

func sendConfirmHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	s, err := acquireSession()
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}
	defer releaseSession(s)

	token := stringArg(req, "confirm_token")
	if token == "" {
		return mcp.NewToolResultError("confirm_token は必須です。"), nil
	}

	// トークンを検証（期限チェック→ワンタイム消費の順でアトミックに実行）
	pending, err := tokenStore.Consume(token)
	if err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	// F1対策: レート制限チェック+予約をatomicに
	if err := reserveSendSlot(); err != nil {
		return mcp.NewToolResultError(err.Error()), nil
	}

	toList := parseAddresses(pending.To)
	if len(toList) == 0 {
		releaseSendSlot()
		return mcp.NewToolResultError("有効な宛先アドレスがありません。メールアドレスを確認してください。"), nil
	}
	ccList := parseAddresses(pending.CC)

	addrKR, ok := s.addrKRs[s.addrID]
	if !ok {
		releaseSendSlot()
		return mcp.NewToolResultError("送信者のキーリングが見つかりません。"), nil
	}

	// 1. ドラフト作成
	draft, err := s.client.CreateDraft(ctx, addrKR, proton.CreateDraftReq{
		Message: proton.DraftTemplate{
			Subject:  pending.Subject,
			Sender:   s.addr,
			ToList:   toList,
			CCList:   ccList,
			Body:     pending.Body,
			MIMEType: rfc822.TextPlain,
		},
	})
	if err != nil {
		releaseSendSlot()
		return mcp.NewToolResultError(fmt.Sprintf("ドラフト作成失敗: %v", err)), nil
	}

	// 2. 添付ファイルのアップロード
	attKeys := make(map[string]*crypto.SessionKey)
	var totalAttSize int64
	if len(pending.Attachments) > 0 {
		for _, filePath := range pending.Attachments {
			// 送信時に再検証（TOCTOU対策）
			validPath, err := validateAttachmentPath(filePath)
			if err != nil {
				_ = s.client.DeleteMessage(ctx, draft.ID)
				releaseSendSlot()
				return mcp.NewToolResultError(fmt.Sprintf("添付ファイルエラー: %s: %v", filePath, err)), nil
			}
			fileData, err := os.ReadFile(validPath)
			if err != nil {
				_ = s.client.DeleteMessage(ctx, draft.ID)
				releaseSendSlot()
				return mcp.NewToolResultError(fmt.Sprintf("添付ファイル読み込み失敗: %s: %v", filePath, err)), nil
			}
			totalAttSize += int64(len(fileData))
			if totalAttSize > maxTotalAttSize {
				_ = s.client.DeleteMessage(ctx, draft.ID)
				releaseSendSlot()
				return mcp.NewToolResultError("添付ファイルの合計サイズが上限（25MB）を超えています"), nil
			}

			mimeType := detectMIMEType(filePath)
			att, err := s.client.UploadAttachment(ctx, addrKR, proton.CreateAttachmentReq{
				MessageID:   draft.ID,
				Filename:    filepath.Base(filePath),
				MIMEType:    rfc822.MIMEType(mimeType),
				Disposition: proton.AttachmentDisposition,
				Body:        fileData,
			})
			if err != nil {
				_ = s.client.DeleteMessage(ctx, draft.ID)
				releaseSendSlot()
				return mcp.NewToolResultError(fmt.Sprintf("添付アップロード失敗: %s: %v", filePath, err)), nil
			}

			// 添付のセッションキーを復号して保存（失敗は致命的エラー）
			kpBytes, err := base64.StdEncoding.DecodeString(att.KeyPackets)
			if err != nil {
				_ = s.client.DeleteMessage(ctx, draft.ID)
				releaseSendSlot()
				return mcp.NewToolResultError(fmt.Sprintf("添付キーパケット復号失敗: %s: %v", filePath, err)), nil
			}
			sk, err := addrKR.DecryptSessionKey(kpBytes)
			if err != nil {
				_ = s.client.DeleteMessage(ctx, draft.ID)
				releaseSendSlot()
				return mcp.NewToolResultError(fmt.Sprintf("添付セッションキー復号失敗: %s: %v", filePath, err)), nil
			}
			attKeys[att.ID] = sk
			fileData = nil // メモリ解放を促す
		}
	}

	// 3. 各宛先のSendPreferencesを構築
	allRecipients := make([]*mail.Address, 0, len(toList)+len(ccList))
	allRecipients = append(allRecipients, toList...)
	allRecipients = append(allRecipients, ccList...)
	prefs := make(map[string]proton.SendPreferences)

	for _, rcpt := range allRecipients {
		pubKeys, recipientType, err := s.client.GetPublicKeys(ctx, rcpt.Address)
		if err != nil || recipientType != proton.RecipientTypeInternal || len(pubKeys) == 0 {
			prefs[rcpt.Address] = proton.SendPreferences{
				Encrypt:          false,
				SignatureType:    proton.NoSignature,
				EncryptionScheme: proton.ClearScheme,
				MIMEType:         rfc822.TextPlain,
			}
		} else {
			recipientKR, err := pubKeys.GetKeyRing()
			if err != nil {
				prefs[rcpt.Address] = proton.SendPreferences{
					Encrypt:          false,
					SignatureType:    proton.NoSignature,
					EncryptionScheme: proton.ClearScheme,
					MIMEType:         rfc822.TextPlain,
				}
			} else {
				prefs[rcpt.Address] = proton.SendPreferences{
					Encrypt:          true,
					PubKey:           recipientKR,
					SignatureType:    proton.DetachedSignature,
					EncryptionScheme: proton.InternalScheme,
					MIMEType:         rfc822.TextPlain,
				}
			}
		}
	}

	// 3. 送信パッケージを構築
	var sendReq proton.SendDraftReq
	if err := sendReq.AddTextPackage(addrKR, pending.Body, rfc822.TextPlain, prefs, attKeys); err != nil {
		_ = s.client.DeleteMessage(ctx, draft.ID)
		releaseSendSlot()
		return mcp.NewToolResultError(fmt.Sprintf("送信パッケージ構築失敗: %v", err)), nil
	}

	// 4. 送信
	sent, err := s.client.SendDraft(ctx, draft.ID, sendReq)
	if err != nil {
		_ = s.client.DeleteMessage(ctx, draft.ID)
		releaseSendSlot()
		return mcp.NewToolResultError(fmt.Sprintf("送信失敗: %v", err)), nil
	}
	// 成功: 枠はreserveSendSlotで消費済み

	result := map[string]interface{}{
		"status":  "送信完了",
		"id":      sent.ID,
		"subject": sent.Subject,
		"to":      formatMailAddresses(sent.ToList),
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("JSON変換失敗: %v", err)), nil
	}
	return mcp.NewToolResultText(string(out)), nil
}

// --- package-level wrappers delegating to internal/* ---

func parseAddresses(s string) []*mail.Address {
	return mailpkg.ParseAddresses(s)
}

func generateToken() (string, error) {
	return security.GenerateToken()
}

func generateTOTPCode(secret string, t time.Time) (string, error) {
	return auth.GenerateTOTPCode(secret, t)
}

func sanitizeEmailBody(body string) string {
	return security.SanitizeEmailBody(body)
}

func validateAttachmentPath(path string) (string, error) {
	return security.ValidateAttachmentPath(path, maxAttachmentSize)
}

func detectMIMEType(filePath string) string {
	return mailpkg.DetectMIMEType(filePath)
}

func reserveSendSlot() error {
	return rateLimiter.Reserve()
}

func releaseSendSlot() {
	rateLimiter.Release()
}

func stringArg(req mcp.CallToolRequest, key string) string {
	return mcppkg.StringArg(req, key)
}

func intArg(req mcp.CallToolRequest, key string, defaultVal int) int {
	return mcppkg.IntArg(req, key, defaultVal)
}

func clampInt(v, min, max int) int {
	return mailpkg.ClampInt(v, min, max)
}

func folderToLabel(folder string) string {
	return mailpkg.FolderToLabel(folder)
}

func formatMailAddress(addr *mail.Address) string {
	return mailpkg.FormatMailAddress(addr)
}

func formatMailAddresses(addrs []*mail.Address) string {
	return mailpkg.FormatMailAddresses(addrs)
}
