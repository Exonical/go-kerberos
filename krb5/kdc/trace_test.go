package kdc

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestTraceASAndTGSExchange(t *testing.T) {
	server, kclient := testServer(t, time.Unix(2000000000, 0).UTC())
	var serverMessages []string
	server.Trace = func(message string) {
		serverMessages = append(serverMessages, message)
	}
	var clientMessages []string
	kclient.Trace = func(message string) {
		clientMessages = append(clientMessages, message)
	}
	user := principalForKDC("alice")
	creds, err := kclient.ASExchange(context.Background(), user, "alice-password")
	if err != nil {
		t.Fatal(err)
	}
	service := principalForKDC("host", "service.test")
	service.Realm = ""
	if _, err := kclient.TGSExchange(context.Background(), creds, service); err != nil {
		t.Fatal(err)
	}
	assertTraceContains(t, serverMessages, "AS-REQ: client alice@TEST.REALM for krbtgt/TEST.REALM@TEST.REALM")
	assertTraceContains(t, serverMessages, "AS-REQ: issuing ticket")
	assertTraceContains(t, serverMessages, "TGS-REQ: service host/service.test@TEST.REALM")
	assertTraceContains(t, serverMessages, "TGS-REQ: issuing ticket")
	assertTraceContains(t, clientMessages, "Getting initial credentials for alice@TEST.REALM")
	assertTraceContains(t, clientMessages, "Requesting tickets for host/service.test@TEST.REALM")
	assertTraceContains(t, clientMessages, "Sending request (")
	assertTraceContains(t, clientMessages, "Received answer (")
}

func assertTraceContains(t *testing.T, messages []string, fragment string) {
	t.Helper()
	for _, message := range messages {
		if strings.Contains(message, fragment) {
			return
		}
	}
	t.Fatalf("trace messages %v do not contain %q", messages, fragment)
}
