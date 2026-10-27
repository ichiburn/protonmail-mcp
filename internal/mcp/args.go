package mcp

import (
	mcpgo "github.com/mark3labs/mcp-go/mcp"
)

// StringArg extracts a string tool argument from a CallToolRequest.
func StringArg(req mcpgo.CallToolRequest, key string) string {
	args := req.GetArguments()
	if args == nil {
		return ""
	}
	v, ok := args[key].(string)
	if !ok {
		return ""
	}
	return v
}

// IntArg extracts a numeric tool argument (JSON float64 or int) from a CallToolRequest.
func IntArg(req mcpgo.CallToolRequest, key string, defaultVal int) int {
	args := req.GetArguments()
	if args == nil {
		return defaultVal
	}
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	default:
		return defaultVal
	}
}
