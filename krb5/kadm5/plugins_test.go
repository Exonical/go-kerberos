package kadm5

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/Exonical/go-kerberos/krb5/crypto"
	"github.com/Exonical/go-kerberos/krb5/kdb"
	"github.com/Exonical/go-kerberos/krb5/principal"
)

func TestPasswordQualityBuiltins(t *testing.T) {
	name, err := principal.Parse("Alice/admin@EXAMPLE.COM")
	if err != nil {
		t.Fatal(err)
	}
	dictPath := filepath.Join(t.TempDir(), "dict")
	if err := os.WriteFile(dictPath, []byte("Birds\n"), 0600); err != nil {
		t.Fatal(err)
	}
	dict := NewDictionaryPasswordQuality(dictPath)
	tests := []struct {
		name     string
		module   PasswordQualityModule
		password string
		policy   string
		want     uint32
	}{
		{"empty", EmptyPasswordQuality{}, "", "", PassQualityTooShort},
		{"princ", PrincipalPasswordQuality{}, "admin", "policy", PassQualityDict},
		{"dict", dict, "birds", "policy", PassQualityDict},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.module.Check(test.password, test.policy, *name)
			var quality *PasswordQualityError
			if !errors.As(err, &quality) || quality.Code != test.want {
				t.Fatalf("Check = %v, want quality code %d", err, test.want)
			}
		})
	}
	if err := dict.Check("birds", "", *name); err != nil {
		t.Fatalf("dictionary without policy = %v", err)
	}
}

type recordingHook struct {
	name   string
	events *[]HookEvent
	err    error
}

func (h recordingHook) Name() string { return h.name }
func (h recordingHook) Handle(event HookEvent) error {
	*h.events = append(*h.events, event)
	return h.err
}

type stageHook struct {
	name   string
	events *[]HookEvent
	err    error
	stage  HookStage
}

func (h stageHook) Name() string { return h.name }
func (h stageHook) Handle(event HookEvent) error {
	*h.events = append(*h.events, event)
	if event.Stage == h.stage {
		return h.err
	}
	return nil
}

type deletePolicyHook struct {
	db   *kdb.Database
	name string
}

func (h deletePolicyHook) Name() string { return "delete-policy" }
func (h deletePolicyHook) Handle(event HookEvent) error {
	if event.Stage == HookPreCommit {
		return h.db.DeletePolicy(h.name)
	}
	return nil
}

func dispatchStatus(t *testing.T, server *Server, client principal.Principal, proc uint32, body []byte) uint32 {
	t.Helper()
	reply := server.dispatch(client, proc, body)
	reader := xdrReader{b: reply}
	_, err := reader.u32()
	if err != nil {
		t.Fatal(err)
	}
	code, err := reader.u32()
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestKadm5HooksLifecycleAndPrecommit(t *testing.T) {
	const realm = "EXAMPLE.COM"
	db := kdb.NewDatabase(realm)
	client, _ := principal.Parse("admin/admin@" + realm)
	if err := db.AddPrincipal("admin/admin@"+realm, "admin-password", 1); err != nil {
		t.Fatal(err)
	}
	var events []HookEvent
	server := &Server{Database: db, API: APIv4, AdminPrincipal: *client,
		Hooks: []Kadm5Hook{recordingHook{name: "first", events: &events}, recordingHook{name: "second", events: &events}}}
	target, _ := principal.Parse("alice@" + realm)
	body := xdrWriter{}
	body.u32(APIv4)
	writeEmptyEntry(&body, *target)
	body.i32(1)
	body.nullString("alice-password")
	if code := dispatchStatus(t, server, *client, createPrincipal, body.bytes()); code != 0 {
		t.Fatalf("create status = %d", code)
	}
	if len(events) != 4 || events[0].Stage != HookPreCommit || events[2].Stage != HookPostCommit {
		t.Fatalf("events = %+v", events)
	}
	events = nil
	server.Hooks = []Kadm5Hook{
		recordingHook{name: "reject", events: &events, err: errors.New("blocked")},
		recordingHook{name: "unreached", events: &events},
	}
	other, _ := principal.Parse("blocked@" + realm)
	body = xdrWriter{}
	body.u32(APIv4)
	writeEmptyEntry(&body, *other)
	body.i32(1)
	body.nullString("password")
	if code := dispatchStatus(t, server, *client, createPrincipal, body.bytes()); code == 0 {
		t.Fatal("precommit failure was accepted")
	}
	if len(events) != 1 || events[0].Stage != HookPreCommit {
		t.Fatalf("short-circuit events = %+v", events)
	}
	if _, ok, _ := db.Lookup(*other); ok {
		t.Fatal("precommit failure committed principal")
	}
}

func TestKadm5HookPostcommitFailureIsLogged(t *testing.T) {
	const realm = "EXAMPLE.COM"
	db := kdb.NewDatabase(realm)
	client, _ := principal.Parse("admin/admin@" + realm)
	_ = db.AddPrincipal("admin/admin@"+realm, "admin-password", 1)
	var logged []error
	var events []HookEvent
	server := &Server{Database: db, API: APIv4, AdminPrincipal: *client,
		ErrorLog: func(err error) { logged = append(logged, err) },
		Hooks: []Kadm5Hook{
			stageHook{name: "post-fails-1", events: &events, err: errors.New("post 1"), stage: HookPostCommit},
			stageHook{name: "post-fails-2", events: &events, err: errors.New("post 2"), stage: HookPostCommit},
		}}
	target, _ := principal.Parse("alice@" + realm)
	body := xdrWriter{}
	body.u32(APIv4)
	writeEmptyEntry(&body, *target)
	body.i32(1)
	body.nullString("password")
	if code := dispatchStatus(t, server, *client, createPrincipal, body.bytes()); code != 0 {
		t.Fatalf("create status = %d", code)
	}
	if len(logged) != 2 || len(events) != 4 {
		t.Fatalf("logged = %v", logged)
	}
	if _, ok, _ := db.Lookup(*target); !ok {
		t.Fatal("postcommit failure rolled back principal")
	}
}

func TestKadm5HooksDispatchAllMutationEvents(t *testing.T) {
	const realm = "EXAMPLE.COM"
	db := kdb.NewDatabase(realm)
	client, _ := principal.Parse("admin/admin@" + realm)
	target, _ := principal.Parse("alice@" + realm)
	_ = db.AddPrincipal("admin/admin@"+realm, "admin-password", 1)
	_ = db.AddPrincipal("alice@"+realm, "alice-password", 1)
	var events []HookEvent
	server := &Server{Database: db, API: APIv4, AdminPrincipal: *client,
		Hooks: []Kadm5Hook{recordingHook{name: "recorder", events: &events}}}

	modify := xdrWriter{}
	modify.u32(APIv4)
	writeEntry(&modify, PrincipalEntry{Principal: *target, Attributes: 1}, KADM5Attributes)
	modify.i32(KADM5Attributes)
	if code := dispatchStatus(t, server, *client, modifyPrincipal, modify.bytes()); code != 0 {
		t.Fatalf("modify status = %d", code)
	}
	renameTarget, _ := principal.Parse("renamed@" + realm)
	rename := xdrWriter{}
	rename.u32(APIv4)
	rename.principal(*target)
	rename.principal(*renameTarget)
	if code := dispatchStatus(t, server, *client, renamePrincipal, rename.bytes()); code != 0 {
		t.Fatalf("rename status = %d", code)
	}
	chpass := xdrWriter{}
	chpass.u32(APIv4)
	chpass.principal(*renameTarget)
	chpass.nullString("new-password")
	if code := dispatchStatus(t, server, *client, chpassPrincipal, chpass.bytes()); code != 0 {
		t.Fatalf("chpass status = %d", code)
	}
	remove := xdrWriter{}
	remove.u32(APIv4)
	remove.principal(*renameTarget)
	if code := dispatchStatus(t, server, *client, deletePrincipal, remove.bytes()); code != 0 {
		t.Fatalf("remove status = %d", code)
	}
	var operations []string
	for _, event := range events {
		if event.Stage == HookPreCommit {
			operations = append(operations, event.Operation)
		}
	}
	want := []string{"modify", "rename", "chpass", "remove"}
	if len(operations) != len(want) {
		t.Fatalf("operations = %v, want %v", operations, want)
	}
	for i := range want {
		if operations[i] != want[i] {
			t.Fatalf("operations = %v, want %v", operations, want)
		}
	}
}

func TestKadm5CreateAppliesPasswordPolicy(t *testing.T) {
	const realm = "EXAMPLE.COM"
	db := kdb.NewDatabase(realm)
	client, _ := principal.Parse("admin/admin@" + realm)
	_ = db.AddPrincipal("admin/admin@"+realm, "admin-password", 1)
	if err := db.CreatePolicy(kdb.PolicyRecord{Name: "strong", MinLength: 12}); err != nil {
		t.Fatal(err)
	}
	target, _ := principal.Parse("alice@" + realm)
	body := xdrWriter{}
	body.u32(APIv4)
	writeEntry(&body, PrincipalEntry{Principal: *target, Policy: "strong"}, KADM5Policy)
	body.i32(KADM5Policy)
	body.nullString("short")
	if code := dispatchStatus(t, &Server{Database: db, API: APIv4, AdminPrincipal: *client},
		*client, createPrincipal, body.bytes()); code != passTooShort {
		t.Fatalf("create status = %d, want %d", code, passTooShort)
	}
	body = xdrWriter{}
	body.u32(APIv4)
	writeEntry(&body, PrincipalEntry{Principal: *target, Policy: "strong"}, KADM5Policy)
	body.i32(KADM5Policy)
	body.nullString("long-enough-password")
	server := &Server{Database: db, API: APIv4, AdminPrincipal: *client}
	if code := dispatchStatus(t, server, *client, createPrincipal, body.bytes()); code != 0 {
		t.Fatalf("create status = %d", code)
	}
	record, ok, err := db.Lookup(*target)
	if err != nil || !ok {
		t.Fatalf("lookup created principal: %v", err)
	}
	if record.Policy != "strong" {
		t.Fatalf("policy = %q, want strong", record.Policy)
	}
}

func TestKadm5CreateRejectsPolicyDeletedBetweenValidationAndCommit(t *testing.T) {
	const realm = "EXAMPLE.COM"
	db := kdb.NewDatabase(realm)
	client, _ := principal.Parse("admin/admin@" + realm)
	target, _ := principal.Parse("alice@" + realm)
	if err := db.AddPrincipal("admin/admin@"+realm, "admin-password", 1); err != nil {
		t.Fatal(err)
	}
	if err := db.CreatePolicy(kdb.PolicyRecord{Name: "ephemeral", MinLength: 8}); err != nil {
		t.Fatal(err)
	}
	server := &Server{
		Database:       db,
		API:            APIv4,
		AdminPrincipal: *client,
		Hooks:          []Kadm5Hook{deletePolicyHook{db: db, name: "ephemeral"}},
	}
	body := xdrWriter{}
	body.u32(APIv4)
	writeEntry(&body, PrincipalEntry{Principal: *target, Policy: "ephemeral"}, KADM5Policy)
	body.i32(KADM5Policy)
	body.nullString("valid-password")
	if code := dispatchStatus(t, server, *client, createPrincipal, body.bytes()); code == 0 {
		t.Fatal("create succeeded after policy was deleted during commit")
	}
	if _, ok, err := db.Lookup(*target); err != nil || ok {
		t.Fatalf("lookup after rejected create = ok %v, err %v", ok, err)
	}
}

func TestDictionaryPasswordQualityIsCached(t *testing.T) {
	const realm = "EXAMPLE.COM"
	db := kdb.NewDatabase(realm)
	name, _ := principal.Parse("alice@" + realm)
	path := filepath.Join(t.TempDir(), "dict")
	if err := os.WriteFile(path, []byte("first\n"), 0600); err != nil {
		t.Fatal(err)
	}
	server := &Server{Database: db, DictionaryFile: path}
	if err := server.checkPasswordQuality("first", "policy", *name); err == nil {
		t.Fatal("first dictionary word was accepted")
	}
	if err := os.WriteFile(path, []byte("second\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := server.checkPasswordQuality("first", "policy", *name); err == nil {
		t.Fatal("cached dictionary word was accepted")
	}
	if err := server.checkPasswordQuality("second", "policy", *name); err != nil {
		t.Fatalf("new dictionary word unexpectedly loaded: %v", err)
	}
}

func TestChpassPrincipal3KeepOldRetainsKVNO(t *testing.T) {
	const realm = "EXAMPLE.COM"
	db := kdb.NewDatabase(realm)
	admin, _ := principal.Parse("admin/admin@" + realm)
	target, _ := principal.Parse("alice@" + realm)
	if err := db.AddPrincipal("admin/admin@"+realm, "admin-password", 1); err != nil {
		t.Fatal(err)
	}
	if err := db.AddPrincipal("alice@"+realm, "old-password", 1); err != nil {
		t.Fatal(err)
	}
	before, ok, err := db.Lookup(*target)
	if err != nil || !ok {
		t.Fatalf("lookup before = %v, %v", err, ok)
	}
	old := before.Keys[crypto.EnctypeAES256SHA1]
	server := &Server{Database: db, API: APIv4, AdminPrincipal: *admin}
	body := xdrWriter{}
	body.u32(APIv4)
	body.principal(*target)
	body.boolean(true)
	body.u32(0)
	body.nullString("new-password")
	if code := dispatchStatus(t, server, *admin, chpassPrincipal3, body.bytes()); code != 0 {
		t.Fatalf("chpass status = %d", code)
	}
	after, ok, err := db.Lookup(*target)
	if err != nil || !ok {
		t.Fatalf("lookup after = %v, %v", err, ok)
	}
	if len(after.PasswordHistory) == 0 || after.PasswordHistory[0][crypto.EnctypeAES256SHA1].KVNO != old.KVNO {
		t.Fatalf("old key history = %#v", after.PasswordHistory)
	}
}
