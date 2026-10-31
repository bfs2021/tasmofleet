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
	for _, u := range []string{"http://hass.lan:8123/api/webhook/b", "http://hass.lan:9999/api/webhook/a", "https://hass.lan:8123/api/webhook/a", "http://hass.lan:8123/api/webhook/a?x=1"} {
		if err := apply(map[string]string{"NOTIFY_WEBHOOK_URL": u}); !errors.As(err, &ve) || ve.Fields["NOTIFY_WEBHOOK_SECRET"] == "" {
			t.Errorf("%s: a changed path, port, scheme or query without the secret must be refused, got %v", u, err)
		}
	}
	if err := apply(map[string]string{"NOTIFY_WEBHOOK_URL": " http://hass.lan:8123/api/webhook/a "}); err != nil {
		t.Fatalf("surrounding white space is no change: %v", err)
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
	c, dropped, err := svc.Preview(map[string]string{"NOTIFY_WEBHOOK_URL": "http://a.lan/h"})
	if err != nil || len(dropped) != 0 || c.NotifyWebhookSecret != "s1" {
		t.Fatalf("same address: %v %v %q", err, dropped, c.NotifyWebhookSecret)
	}
	for _, u := range []string{"http://a.lan/other", "http://a.lan:81/h", "https://a.lan/h", "http://a.lan/h?x=1"} {
		c, dropped, err = svc.Preview(map[string]string{"NOTIFY_WEBHOOK_URL": u})
		if err != nil || len(dropped) != 1 || c.NotifyWebhookSecret != "" {
			t.Errorf("%s: %v %v %q, want the secret left out", u, err, dropped, c.NotifyWebhookSecret)
		}
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

// Why (review): the audit log keeps old and new values of a change. A webhook address can carry
// its secret in the path (Home Assistant) or the query (Gotify), so the audit shows scheme, host
// and port only; the settings page still gets the address as stored, query included, so saving the
// page does not cut a token off.
func TestWebhookAddressIsRedactedInTheAuditButShownWhole(t *testing.T) {
	svc, aud := newSvc(t, newMem())
	res, err := svc.Apply(t.Context(), Request{Actor: "admin", Audit: aud, Values: map[string]string{"NOTIFY_WEBHOOK_URL": "http://hass.lan:8123/api/webhook/secret-id?token=abc"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Changes) != 1 || res.Changes[0].New != "http://hass.lan:8123/***" {
		t.Fatalf("changes: %+v", res.Changes)
	}
	for _, st := range svc.State() {
		if st.Key == "NOTIFY_WEBHOOK_URL" && st.Value != "http://hass.lan:8123/api/webhook/secret-id?token=abc" {
			t.Fatalf("the page value lost part of the address: %q", st.Value)
		}
	}
}
