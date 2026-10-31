package sysconfig

import (
	"errors"
	"testing"
)

// Why (security review): a stored notification secret is bound to the target it was entered for,
// like the MQTT password. A save that moves the webhook (or the mail server) to another host
// without entering the secret again must be refused: otherwise the next message, or the next
// test, would carry the secret to a host the admin chose.
func TestStoredNotificationSecretsAreBoundToTheirTarget(t *testing.T) {
	svc, _ := newSvc(t, newMem())
	apply := func(v map[string]string) error {
		_, err := svc.Apply(t.Context(), Request{Actor: "admin", Values: v})
		return err
	}
	if err := apply(map[string]string{"NOTIFY_WEBHOOK_URL": "http://hass.lan:8123/api/webhook/a", "NOTIFY_WEBHOOK_AUTH": "header", "NOTIFY_WEBHOOK_SECRET": "s1"}); err != nil {
		t.Fatal(err)
	}
	var ve *ValidationError
	if err := apply(map[string]string{"NOTIFY_WEBHOOK_URL": "http://evil.example:8123/api/webhook/a"}); !errors.As(err, &ve) || ve.Fields["NOTIFY_WEBHOOK_SECRET"] == "" {
		t.Fatalf("a new host without the secret must be refused, got %v", err)
	}
	if got := svc.Snapshot(); got.NotifyWebhookURL != "http://hass.lan:8123/api/webhook/a" || got.NotifyWebhookSecret != "s1" {
		t.Fatalf("a refused save changed something: %+v", got)
	}
	if err := apply(map[string]string{"NOTIFY_WEBHOOK_URL": "http://hass.lan:8123/api/webhook/b"}); err != nil {
		t.Fatalf("another path on the same host keeps the secret: %v", err)
	}
	if err := apply(map[string]string{"NOTIFY_WEBHOOK_URL": "http://new.lan/h", "NOTIFY_WEBHOOK_SECRET": "s2"}); err != nil {
		t.Fatalf("a new host with a new secret: %v", err)
	}
	if got := svc.Snapshot().NotifyWebhookSecret; got != "s2" {
		t.Fatalf("secret = %q", got)
	}

	if err := apply(map[string]string{"NOTIFY_SMTP_HOST": "mail.lan", "NOTIFY_SMTP_USER": "u", "NOTIFY_SMTP_PASSWORD": "p1"}); err != nil {
		t.Fatal(err)
	}
	for _, v := range []map[string]string{{"NOTIFY_SMTP_HOST": "evil.example"}, {"NOTIFY_SMTP_PORT": "25"}, {"NOTIFY_SMTP_USER": "other"}, {"NOTIFY_SMTP_SECURITY": "none"}} {
		if err := apply(v); !errors.As(err, &ve) || ve.Fields["NOTIFY_SMTP_PASSWORD"] == "" {
			t.Errorf("%v without the password must be refused, got %v", v, err)
		}
	}
}

// Why: the test button must use the same rule as the save: a form that names another target gets
// no stored secret, and the preview says which one was left out.
func TestPreviewLeavesOutAStoredSecretForAnotherTarget(t *testing.T) {
	svc, _ := newSvc(t, newMem())
	if _, err := svc.Apply(t.Context(), Request{Actor: "admin", Values: map[string]string{"NOTIFY_WEBHOOK_URL": "http://a.lan/h", "NOTIFY_WEBHOOK_AUTH": "header", "NOTIFY_WEBHOOK_SECRET": "s1"}}); err != nil {
		t.Fatal(err)
	}
	c, dropped, err := svc.Preview(map[string]string{"NOTIFY_WEBHOOK_URL": "http://a.lan/other"})
	if err != nil || len(dropped) != 0 || c.NotifyWebhookSecret != "s1" {
		t.Fatalf("same host: %v %v %q", err, dropped, c.NotifyWebhookSecret)
	}
	c, dropped, err = svc.Preview(map[string]string{"NOTIFY_WEBHOOK_URL": "http://b.lan/h"})
	if err != nil || len(dropped) != 1 || dropped[0] != "NOTIFY_WEBHOOK_SECRET" || c.NotifyWebhookSecret != "" {
		t.Fatalf("other host: %v %v %q", err, dropped, c.NotifyWebhookSecret)
	}
	c, dropped, _ = svc.Preview(map[string]string{"NOTIFY_WEBHOOK_URL": "http://b.lan/h", "NOTIFY_WEBHOOK_SECRET": "typed"})
	if len(dropped) != 0 || c.NotifyWebhookSecret != "typed" {
		t.Fatalf("typed: %v %q", dropped, c.NotifyWebhookSecret)
	}
}
