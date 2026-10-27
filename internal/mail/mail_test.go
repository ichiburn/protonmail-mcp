package mail

import (
	netmail "net/mail"
	"testing"

	proton "github.com/ProtonMail/go-proton-api"
)

func TestParseAddresses_CRLFAndEmptyRejection(t *testing.T) {
	t.Run("empty_and_whitespace_rejected", func(t *testing.T) {
		if got := ParseAddresses(""); len(got) != 0 {
			t.Fatalf("expected empty result for empty string, got %v", got)
		}
		if got := ParseAddresses("   ,  , \t "); len(got) != 0 {
			t.Fatalf("expected empty result for whitespace commas, got %v", got)
		}
	})

	t.Run("valid_single_and_multiple_addresses", func(t *testing.T) {
		got := ParseAddresses("alice@example.com, Bob Smith <bob@example.org>")
		if len(got) != 2 {
			t.Fatalf("expected 2 addresses, got %d", len(got))
		}
		if got[0].Address != "alice@example.com" {
			t.Errorf("expected alice@example.com, got %q", got[0].Address)
		}
		if got[1].Address != "bob@example.org" || got[1].Name != "Bob Smith" {
			t.Errorf("unexpected second address: %+v", got[1])
		}
	})

	t.Run("crlf_header_injection_rejected", func(t *testing.T) {
		injections := []string{
			"victim@example.com\r\nBcc: attacker@evil.example",
			"victim@example.com\nBcc: attacker@evil.example",
			"victim@example.com\rBcc: attacker@evil.example",
			"\"Evil\r\nName\" <victim@example.com>",
			"valid@example.com, injected@example.com\r\nSubject: Pwned",
		}
		for _, input := range injections {
			got := ParseAddresses(input)
			for _, addr := range got {
				if addr.Address == "victim@example.com" || addr.Address == "injected@example.com" || addr.Address == "attacker@evil.example" {
					t.Fatalf("CRLF-injected address was not rejected for input %q: got %+v", input, addr)
				}
			}
		}
		// In the mixed case ("valid@example.com, injected@..."), only valid@example.com should survive
		mixed := ParseAddresses("valid@example.com, injected@example.com\r\nBcc: spy@evil.example")
		if len(mixed) != 1 || mixed[0].Address != "valid@example.com" {
			t.Fatalf("expected only valid@example.com to survive mixed input, got %+v", mixed)
		}
	})

	t.Run("malformed_addresses_ignored", func(t *testing.T) {
		if got := ParseAddresses("not-an-email, @missing-local.com, user@"); len(got) != 0 {
			t.Fatalf("expected 0 valid addresses for malformed inputs, got %+v", got)
		}
	})
}

func TestClampInt(t *testing.T) {
	cases := []struct {
		v, min, max, want int
	}{
		{-10, 1, 150, 1},
		{0, 1, 150, 1},
		{1, 1, 150, 1},
		{20, 1, 150, 20},
		{150, 1, 150, 150},
		{999, 1, 150, 150},
		{-5, 0, 1000, 0},
		{0, 0, 1000, 0},
		{500, 0, 1000, 500},
		{5000, 0, 1000, 1000},
	}
	for _, tc := range cases {
		if got := ClampInt(tc.v, tc.min, tc.max); got != tc.want {
			t.Errorf("ClampInt(%d, %d, %d) = %d, want %d", tc.v, tc.min, tc.max, got, tc.want)
		}
	}
}

func TestFolderToLabel(t *testing.T) {
	if FolderToLabel("inbox") != proton.InboxLabel {
		t.Error("inbox mismatch")
	}
	if FolderToLabel("SENT") != proton.SentLabel {
		t.Error("sent mismatch")
	}
	if FolderToLabel("Drafts") != proton.DraftsLabel {
		t.Error("drafts mismatch")
	}
	if FolderToLabel("trash") != proton.TrashLabel {
		t.Error("trash mismatch")
	}
	if FolderToLabel("spam") != proton.SpamLabel {
		t.Error("spam mismatch")
	}
	if FolderToLabel("archive") != proton.ArchiveLabel {
		t.Error("archive mismatch")
	}
	if FolderToLabel("all") != proton.AllMailLabel {
		t.Error("all mismatch")
	}
	if FolderToLabel("unknown-folder") != proton.InboxLabel {
		t.Error("default fallback mismatch")
	}
}

func TestFormatMailAddressesAndMIME(t *testing.T) {
	if FormatMailAddress(nil) != "" {
		t.Error("expected empty string for nil address")
	}
	a1 := &netmail.Address{Address: "a@example.com"}
	a2 := &netmail.Address{Name: "Alice", Address: "alice@example.com"}
	if got := FormatMailAddresses([]*netmail.Address{a1, a2}); got != "a@example.com, Alice <alice@example.com>" {
		t.Errorf("unexpected FormatMailAddresses: %q", got)
	}

	if DetectMIMEType("doc.PDF") != "application/pdf" {
		t.Error("expected application/pdf")
	}
	if DetectMIMEType("image.png") != "image/png" {
		t.Error("expected image/png")
	}
	if DetectMIMEType("unknown.bin") != "application/octet-stream" {
		t.Error("expected application/octet-stream")
	}
}
