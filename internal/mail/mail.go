package mail

import (
	"fmt"
	netmail "net/mail"
	"path/filepath"
	"strings"

	proton "github.com/ProtonMail/go-proton-api"
)

// ParseAddresses parses a comma-separated list of email addresses, rejecting any entry
// containing CRLF characters (\r or \n) to prevent SMTP header injection.
func ParseAddresses(s string) []*netmail.Address {
	if s == "" {
		return nil
	}
	var addrs []*netmail.Address
	for _, part := range strings.Split(s, ",") {
		// Reject CRLF injection before and after trimming
		if strings.ContainsAny(part, "\r\n") {
			continue
		}
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		addr, err := netmail.ParseAddress(part)
		if err != nil {
			addr, err = netmail.ParseAddress("<" + part + ">")
			if err != nil {
				continue
			}
		}
		if strings.ContainsAny(addr.Address, "\r\n") || strings.ContainsAny(addr.Name, "\r\n") {
			continue
		}
		addrs = append(addrs, addr)
	}
	return addrs
}

// ClampInt clamps v into the inclusive range [min, max].
func ClampInt(v, min, max int) int {
	if v < min {
		return min
	}
	if v > max {
		return max
	}
	return v
}

// FolderToLabel maps a human-readable folder name to a ProtonMail label ID.
func FolderToLabel(folder string) string {
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

// FormatMailAddress formats a single *net/mail.Address for display.
func FormatMailAddress(addr *netmail.Address) string {
	if addr == nil {
		return ""
	}
	if addr.Name != "" {
		return fmt.Sprintf("%s <%s>", addr.Name, addr.Address)
	}
	return addr.Address
}

// FormatMailAddresses formats a slice of *net/mail.Address as a comma-separated string.
func FormatMailAddresses(addrs []*netmail.Address) string {
	var parts []string
	for _, a := range addrs {
		parts = append(parts, FormatMailAddress(a))
	}
	return strings.Join(parts, ", ")
}

// DetectMIMEType returns the MIME type for common attachment file extensions.
func DetectMIMEType(filePath string) string {
	ext := strings.ToLower(filepath.Ext(filePath))
	switch ext {
	case ".pdf":
		return "application/pdf"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".txt":
		return "text/plain"
	case ".html", ".htm":
		return "text/html"
	case ".csv":
		return "text/csv"
	case ".zip":
		return "application/zip"
	case ".doc":
		return "application/msword"
	case ".docx":
		return "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	case ".xls":
		return "application/vnd.ms-excel"
	case ".xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	default:
		return "application/octet-stream"
	}
}
