package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestDiscordPayload(t *testing.T) {
	n := notification{Event: "enrollment", Status: "error", Email: "person@example.test", Error: "Token exchange failed: HTTP 400 (Bad Request)."}
	for _, host := range []string{"discord.com", "discordapp.com"} {
		b, err := json.Marshal(webhookPayload("https://"+host+"/api/webhooks/id/private", n))
		if err != nil {
			t.Fatal(err)
		}
		var v struct {
			Content  string `json:"content"`
			Mentions struct {
				Parse []string `json:"parse"`
			} `json:"allowed_mentions"`
		}
		if json.Unmarshal(b, &v) != nil || !strings.Contains(v.Content, n.Email) || !strings.Contains(v.Content, n.Error) || v.Mentions.Parse == nil || len(v.Mentions.Parse) != 0 {
			t.Fatalf("bad payload: %s", b)
		}
	}
	for _, u := range []string{"https://example.com/hook", "https://discord.com.evil.test/api/webhooks/id/token", "https://discord.com/other"} {
		if _, ok := webhookPayload(u, n).(notification); !ok {
			t.Fatal("changed generic payload")
		}
	}
	n.Error = strings.Repeat("x", 3000)
	v := webhookPayload("https://discord.com/api/webhooks/id/token", n).(map[string]any)
	if len([]rune(v["content"].(string))) > 2000 {
		t.Fatal("oversized message")
	}
}
