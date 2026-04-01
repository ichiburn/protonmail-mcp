package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/mail"
	"os"
	"strings"
	"time"

	proton "github.com/ProtonMail/go-proton-api"
	"github.com/ProtonMail/gluon/rfc822"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var (
	protonClient *proton.Client
	protonMgr    *proton.Manager
	userKR       *crypto.KeyRing
	addrKRs      map[string]*crypto.KeyRing
	senderAddr   *mail.Address // ログイン時のプライマリアドレス
	senderAddrID string        // アドレスID
)

func main() {
	s := server.NewMCPServer(
		"protonmail",
		"0.1.0",
		server.WithToolCapabilities(true),
	)

	s.AddTool(mcp.NewTool("protonmail_login",
		mcp.WithDescription("ProtonMailにログインする。環境変数 PROTON_USER / PROTON_PASS が設定されていればそれを使う。"),
		mcp.WithString("username", mcp.Description("ProtonMailユーザー名（環境変数未設定時）")),
		mcp.WithString("password", mcp.Description("ProtonMailパスワード（環境変数未設定時）")),
		mcp.WithString("totp", mcp.Description("2FAコード（有効な場合）")),
	), loginHandler)

	s.AddTool(mcp.NewTool("protonmail_list_messages",
		mcp.WithDescription("メール一覧を取得する。フォルダやキーワードでフィルタ可能。"),
		mcp.WithString("folder", mcp.Description("フォルダ: inbox, sent, drafts, trash, spam, archive, all (デフォルト: inbox)")),
		mcp.WithString("subject", mcp.Description("件名フィルタ")),
		mcp.WithNumber("limit", mcp.Description("取得件数 (デフォルト: 20)")),
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
		mcp.WithNumber("limit", mcp.Description("取得件数 (デフォルト: 20)")),
	), searchMessagesHandler)

	s.AddTool(mcp.NewTool("protonmail_send_message",
		mcp.WithDescription("メールを送信する。"),
		mcp.WithString("to", mcp.Required(), mcp.Description("宛先メールアドレス（カンマ区切りで複数可）")),
		mcp.WithString("subject", mcp.Required(), mcp.Description("件名")),
		mcp.WithString("body", mcp.Required(), mcp.Description("本文（プレーンテキスト）")),
		mcp.WithString("cc", mcp.Description("CCメールアドレス（カンマ区切り）")),
	), sendMessageHandler)

	if err := server.ServeStdio(s); err != nil {
		log.Fatal(err)
	}
}

func loginHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	username := stringArg(req, "username")
	password := stringArg(req, "password")
	totp := stringArg(req, "totp")

	if username == "" {
		username = os.Getenv("PROTON_USER")
	}
	if password == "" {
		password = os.Getenv("PROTON_PASS")
	}
	if username == "" || password == "" {
		return mcp.NewToolResultError("username/password が必要です。引数か環境変数 PROTON_USER/PROTON_PASS を設定してください。"), nil
	}

	protonMgr = proton.New(
		proton.WithHostURL("https://mail.proton.me/api"),
		proton.WithAppVersion("Other"),
	)

	c, auth, err := protonMgr.NewClientWithLogin(ctx, username, []byte(password))
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("ログイン失敗: %v", err)), nil
	}

	if auth.TwoFA.Enabled&proton.HasTOTP != 0 {
		if totp == "" {
			return mcp.NewToolResultError("2FAが有効です。totp パラメータに認証コードを指定してください。"), nil
		}
		if err := c.Auth2FA(ctx, proton.Auth2FAReq{TwoFactorCode: totp}); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("2FA認証失敗: %v", err)), nil
		}
	}

	protonClient = c

	user, err := c.GetUser(ctx)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("ユーザー情報取得失敗: %v", err)), nil
	}

	salts, err := c.GetSalts(ctx)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("Salt取得失敗: %v", err)), nil
	}

	addrs, err := c.GetAddresses(ctx)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("アドレス取得失敗: %v", err)), nil
	}

	saltedKeyPass, err := salts.SaltForKey([]byte(password), user.Keys.Primary().ID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("鍵パスフレーズ導出失敗: %v", err)), nil
	}

	ukr, akrs, err := proton.Unlock(user, addrs, saltedKeyPass)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("キーリングアンロック失敗: %v", err)), nil
	}

	userKR = ukr
	addrKRs = akrs

	// プライマリアドレスを保存
	if len(addrs) > 0 {
		senderAddr = &mail.Address{Name: user.Name, Address: addrs[0].Email}
		senderAddrID = addrs[0].ID
	}

	return mcp.NewToolResultText(fmt.Sprintf("ログイン成功: %s (%s)", user.Name, user.Email)), nil
}

func listMessagesHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if protonClient == nil {
		return mcp.NewToolResultError("未ログインです。先に protonmail_login を実行してください。"), nil
	}

	folder := stringArg(req, "folder")
	if folder == "" {
		folder = "inbox"
	}
	subject := stringArg(req, "subject")
	limit := intArg(req, "limit", 20)
	page := intArg(req, "page", 0)

	labelID := folderToLabel(folder)

	filter := proton.MessageFilter{
		LabelID: labelID,
	}
	if subject != "" {
		filter.Subject = subject
	}

	msgs, err := protonClient.GetMessageMetadataPage(ctx, page, limit, filter)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("メール取得失敗: %v", err)), nil
	}

	var results []map[string]interface{}
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

	if results == nil {
		results = []map[string]interface{}{}
	}

	out, _ := json.MarshalIndent(results, "", "  ")
	return mcp.NewToolResultText(string(out)), nil
}

func readMessageHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if protonClient == nil {
		return mcp.NewToolResultError("未ログインです。先に protonmail_login を実行してください。"), nil
	}
	if userKR == nil {
		return mcp.NewToolResultError("キーリングが未初期化です。再ログインしてください。"), nil
	}

	msgID := stringArg(req, "message_id")
	if msgID == "" {
		return mcp.NewToolResultError("message_id は必須です。"), nil
	}

	msg, err := protonClient.GetMessage(ctx, msgID)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("メッセージ取得失敗: %v", err)), nil
	}

	kr, ok := addrKRs[msg.AddressID]
	if !ok {
		return mcp.NewToolResultError("このメッセージのアドレスに対応するキーリングがありません。"), nil
	}

	decrypted, err := msg.Decrypt(kr)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("復号失敗: %v", err)), nil
	}

	result := map[string]interface{}{
		"id":      msg.ID,
		"subject": msg.Subject,
		"sender":  formatMailAddress(msg.Sender),
		"to":      formatMailAddresses(msg.ToList),
		"cc":      formatMailAddresses(msg.CCList),
		"date":    time.Unix(msg.Time, 0).Format("2006-01-02 15:04"),
		"body":    string(decrypted),
	}

	out, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(out)), nil
}

func searchMessagesHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if protonClient == nil {
		return mcp.NewToolResultError("未ログインです。先に protonmail_login を実行してください。"), nil
	}

	sender := strings.ToLower(stringArg(req, "sender"))
	subject := stringArg(req, "subject")
	keyword := strings.ToLower(stringArg(req, "keyword"))
	limit := intArg(req, "limit", 20)

	filter := proton.MessageFilter{
		LabelID: proton.AllMailLabel,
	}
	if subject != "" {
		filter.Subject = subject
	}

	fetchLimit := limit * 3
	if fetchLimit < 50 {
		fetchLimit = 50
	}

	msgs, err := protonClient.GetMessageMetadataPage(ctx, 0, fetchLimit, filter)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("検索失敗: %v", err)), nil
	}

	var results []map[string]interface{}
	for _, m := range msgs {
		if sender != "" {
			senderAddr := strings.ToLower(m.Sender.Address)
			senderName := strings.ToLower(m.Sender.Name)
			if !strings.Contains(senderAddr, sender) && !strings.Contains(senderName, sender) {
				continue
			}
		}

		if keyword != "" {
			if !strings.Contains(strings.ToLower(m.Subject), keyword) {
				continue
			}
		}

		entry := map[string]interface{}{
			"id":      m.ID,
			"subject": m.Subject,
			"sender":  formatMailAddress(m.Sender),
			"date":    time.Unix(m.Time, 0).Format("2006-01-02 15:04"),
			"unread":  bool(m.Unread),
		}

		results = append(results, entry)
		if len(results) >= limit {
			break
		}
	}

	if results == nil {
		results = []map[string]interface{}{}
	}

	out, _ := json.MarshalIndent(results, "", "  ")
	return mcp.NewToolResultText(string(out)), nil
}

func sendMessageHandler(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if protonClient == nil {
		return mcp.NewToolResultError("未ログインです。先に protonmail_login を実行してください。"), nil
	}
	if senderAddr == nil {
		return mcp.NewToolResultError("送信者アドレスが未設定です。再ログインしてください。"), nil
	}

	to := stringArg(req, "to")
	subject := stringArg(req, "subject")
	body := stringArg(req, "body")
	cc := stringArg(req, "cc")

	if to == "" || subject == "" || body == "" {
		return mcp.NewToolResultError("to, subject, body は必須です。"), nil
	}

	toList := parseAddresses(to)
	ccList := parseAddresses(cc)

	addrKR, ok := addrKRs[senderAddrID]
	if !ok {
		return mcp.NewToolResultError("送信者のキーリングが見つかりません。"), nil
	}

	// 1. ドラフト作成
	draft, err := protonClient.CreateDraft(ctx, addrKR, proton.CreateDraftReq{
		Message: proton.DraftTemplate{
			Subject:  subject,
			Sender:   senderAddr,
			ToList:   toList,
			CCList:   ccList,
			Body:     body,
			MIMEType: rfc822.TextPlain,
		},
	})
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("ドラフト作成失敗: %v", err)), nil
	}

	// 2. 各宛先のSendPreferencesを構築
	allRecipients := append(toList, ccList...)
	prefs := make(map[string]proton.SendPreferences)

	for _, rcpt := range allRecipients {
		pubKeys, recipientType, err := protonClient.GetPublicKeys(ctx, rcpt.Address)
		if err != nil || recipientType != proton.RecipientTypeInternal || len(pubKeys) == 0 {
			// 外部宛先: 暗号化なし（ClearScheme）
			prefs[rcpt.Address] = proton.SendPreferences{
				Encrypt:          false,
				SignatureType:    proton.NoSignature,
				EncryptionScheme: proton.ClearScheme,
				MIMEType:         rfc822.TextPlain,
			}
		} else {
			// Proton内部宛先: 暗号化あり
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
	if err := sendReq.AddTextPackage(addrKR, body, rfc822.TextPlain, prefs, nil); err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("送信パッケージ構築失敗: %v", err)), nil
	}

	// 4. 送信
	sent, err := protonClient.SendDraft(ctx, draft.ID, sendReq)
	if err != nil {
		return mcp.NewToolResultError(fmt.Sprintf("送信失敗: %v", err)), nil
	}

	result := map[string]interface{}{
		"status":  "送信完了",
		"id":      sent.ID,
		"subject": sent.Subject,
		"to":      formatMailAddresses(sent.ToList),
	}

	out, _ := json.MarshalIndent(result, "", "  ")
	return mcp.NewToolResultText(string(out)), nil
}

func parseAddresses(s string) []*mail.Address {
	if s == "" {
		return nil
	}
	var addrs []*mail.Address
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		addr, err := mail.ParseAddress(part)
		if err != nil {
			addrs = append(addrs, &mail.Address{Address: part})
		} else {
			addrs = append(addrs, addr)
		}
	}
	return addrs
}

// --- helpers ---

func stringArg(req mcp.CallToolRequest, key string) string {
	args := req.GetArguments()
	v, ok := args[key].(string)
	if !ok {
		return ""
	}
	return v
}

func intArg(req mcp.CallToolRequest, key string, defaultVal int) int {
	args := req.GetArguments()
	v, ok := args[key].(float64)
	if !ok {
		return defaultVal
	}
	return int(v)
}

func folderToLabel(folder string) string {
	switch strings.ToLower(folder) {
	case "inbox":
		return proton.InboxLabel
	case "sent":
		return proton.SentLabel
	case "drafts":
		return proton.DraftsLabel
	case "trash":
		return proton.TrashLabel
	case "spam":
		return proton.SpamLabel
	case "archive":
		return proton.ArchiveLabel
	case "all":
		return proton.AllMailLabel
	default:
		return proton.InboxLabel
	}
}

func formatMailAddress(addr *mail.Address) string {
	if addr == nil {
		return ""
	}
	if addr.Name != "" {
		return fmt.Sprintf("%s <%s>", addr.Name, addr.Address)
	}
	return addr.Address
}

func formatMailAddresses(addrs []*mail.Address) string {
	var parts []string
	for _, a := range addrs {
		parts = append(parts, formatMailAddress(a))
	}
	return strings.Join(parts, ", ")
}
