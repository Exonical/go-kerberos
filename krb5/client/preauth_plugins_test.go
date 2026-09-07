package client

import (
	"testing"

	"github.com/Exonical/go-kerberos/krb5/preauth"
	"github.com/Exonical/go-kerberos/krb5/principal"
	"github.com/Exonical/go-kerberos/krb5/protocol"
)

type orderingPreauthModule struct {
	name  string
	flags int
	order *[]string
	pa    int32
}

func (m orderingPreauthModule) Name() string     { return m.name }
func (m orderingPreauthModule) PATypes() []int32 { return []int32{m.pa} }
func (m orderingPreauthModule) Flags(int32) int  { return m.flags }
func (m orderingPreauthModule) Process(_ *preauth.ClientRequestContext, _ preauth.PAData, _ preauth.ASReqInfo) ([]preauth.PAData, error) {
	*m.order = append(*m.order, m.name)
	return []preauth.PAData{{
		PADataType:  m.pa + 100,
		PADataValue: []byte(m.name),
	}}, nil
}

func TestClientPreauthModulesProcessInfoBeforeReal(t *testing.T) {
	var order []string
	request := protocol.ASReq{ReqBody: protocol.KDCReqBody{
		CName: &protocol.PrincipalName{NameType: int32(principal.NTPrincipal), NameString: []string{"alice"}},
	}}
	methodData := protocol.MethodData{
		{PADataType: 2002, PADataValue: []byte("real")},
		{PADataType: 2001, PADataValue: []byte("info")},
	}
	c := &Client{PreauthModules: []preauth.ClientPreauthModule{
		orderingPreauthModule{name: "real", flags: preauth.PAReal, order: &order, pa: 2002},
		orderingPreauthModule{name: "info", flags: preauth.PAInfo, order: &order, pa: 2001},
	}}
	answers, handled, _, err := c.processClientPreauthModules(request, methodData,
		principal.Principal{Realm: "TEST.REALM", Components: []string{"alice"}},
		18, []byte("key"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !handled {
		t.Fatal("real module did not handle preauthentication")
	}
	if len(order) != 2 || order[0] != "info" || order[1] != "real" {
		t.Fatalf("module order = %v", order)
	}
	if len(answers) != 2 {
		t.Fatalf("answer count = %d, want 2", len(answers))
	}
}

func TestClientPreauthModuleAnswerRetainsCookie(t *testing.T) {
	var order []string
	request := protocol.ASReq{ReqBody: protocol.KDCReqBody{
		CName: &protocol.PrincipalName{NameType: int32(principal.NTPrincipal), NameString: []string{"alice"}},
	}}
	methodData := protocol.MethodData{
		{PADataType: 2002, PADataValue: []byte("real")},
		{PADataType: preauth.PADataCookie, PADataValue: []byte("cookie")},
	}
	c := &Client{PreauthModules: []preauth.ClientPreauthModule{
		orderingPreauthModule{name: "real", flags: preauth.PAReal, order: &order, pa: 2002},
	}}
	modulePA, handled, _, err := c.processClientPreauthModules(request, methodData,
		principal.Principal{Realm: "TEST.REALM", Components: []string{"alice"}},
		18, []byte("key"), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !handled {
		t.Fatal("real module did not handle preauthentication")
	}
	outgoing := appendClientPreauthCookie(modulePA, methodData)
	if cookie := preauth.FindPAData(outgoing, preauth.PADataCookie); cookie == nil ||
		string(cookie.PADataValue) != "cookie" {
		t.Fatalf("outgoing padata lost cookie: %#v", outgoing)
	}
}
