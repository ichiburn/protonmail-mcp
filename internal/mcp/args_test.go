package mcp

import (
	"testing"

	mcpgo "github.com/mark3labs/mcp-go/mcp"
)

func TestStringArgAndIntArg(t *testing.T) {
	var req mcpgo.CallToolRequest
	req.Params.Arguments = map[string]interface{}{
		"folder": "sent",
		"limit":  float64(45),
		"page":   3,
	}

	if got := StringArg(req, "folder"); got != "sent" {
		t.Fatalf("expected 'sent', got %q", got)
	}
	if got := StringArg(req, "missing"); got != "" {
		t.Fatalf("expected empty string for missing key, got %q", got)
	}
	if got := IntArg(req, "limit", 20); got != 45 {
		t.Fatalf("expected 45, got %d", got)
	}
	if got := IntArg(req, "page", 0); got != 3 {
		t.Fatalf("expected 3, got %d", got)
	}
	if got := IntArg(req, "missing", 20); got != 20 {
		t.Fatalf("expected default 20, got %d", got)
	}
}
