package kadm5

import (
	"context"
	"errors"
	"fmt"

	"github.com/Exonical/go-kerberos/krb5/principal"
)

// ModifyPrincipal updates the fields selected by mask.
func (c *Client) ModifyPrincipal(ctx context.Context, entry PrincipalEntry, mask int32) error {
	body := xdrWriter{}
	body.u32(c.API)
	writeEntry(&body, entry, mask)
	body.i32(mask)
	return c.genericCall(ctx, modifyPrincipal, body.bytes())
}

// RenamePrincipal renames src to dest.
func (c *Client) RenamePrincipal(ctx context.Context, src, dest principal.Principal) error {
	body := xdrWriter{}
	body.u32(c.API)
	body.principal(src)
	body.principal(dest)
	return c.genericCall(ctx, renamePrincipal, body.bytes())
}

// RandKey changes a principal's keys and returns the generated keyblocks.
func (c *Client) RandKey(ctx context.Context, p principal.Principal) ([]Key, error) {
	body := xdrWriter{}
	body.u32(c.API)
	body.principal(p)
	reply, err := c.call(ctx, chrandPrincipal, body.bytes())
	if err != nil {
		return nil, err
	}
	r, api, code, err := statusReader(reply)
	if err != nil {
		return nil, err
	}
	if err := checkReplyAPI(api, c.API); err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, operationError("CHRAND_PRINCIPAL", code)
	}
	keys, err := readKeys(&r)
	if err != nil {
		return nil, err
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return keys, nil
}

func readKeys(r *xdrReader) ([]Key, error) {
	n, err := r.u32()
	if err != nil {
		return nil, err
	}
	if n > 1<<16 {
		return nil, errors.New("kadm5: oversized random-key array")
	}
	keys := make([]Key, 0, n)
	for i := uint32(0); i < n; i++ {
		enctype, err := r.i32()
		if err != nil {
			return nil, err
		}
		value, err := r.opaque()
		if err != nil {
			return nil, err
		}
		keys = append(keys, Key{Enctype: enctype, Key: value})
	}
	return keys, nil
}

// ListPrincipals returns principals matching expression.
func (c *Client) ListPrincipals(ctx context.Context, expression string) ([]string, error) {
	body := xdrWriter{}
	body.u32(c.API)
	body.nullString(expression)
	reply, err := c.call(ctx, getPrincs, body.bytes())
	if err != nil {
		return nil, err
	}
	r, api, code, err := statusReader(reply)
	if err != nil {
		return nil, err
	}
	if err := checkReplyAPI(api, c.API); err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, operationError("GET_PRINCS", code)
	}
	out, err := readStringList(&r, "principal")
	if err != nil {
		return nil, err
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return out, nil
}

// CreatePolicy creates a policy using the fields selected by mask.
func (c *Client) CreatePolicy(ctx context.Context, policy Policy, mask int32) error {
	body := xdrWriter{}
	body.u32(c.API)
	writePolicy(&body, policy, c.API)
	body.i32(mask)
	return c.genericCall(ctx, createPolicy, body.bytes())
}

// DeletePolicy deletes a policy by name.
func (c *Client) DeletePolicy(ctx context.Context, name string) error {
	body := xdrWriter{}
	body.u32(c.API)
	body.nullString(name)
	return c.genericCall(ctx, deletePolicy, body.bytes())
}

// ModifyPolicy updates a policy using the fields selected by mask.
func (c *Client) ModifyPolicy(ctx context.Context, policy Policy, mask int32) error {
	body := xdrWriter{}
	body.u32(c.API)
	writePolicy(&body, policy, c.API)
	body.i32(mask)
	return c.genericCall(ctx, modifyPolicy, body.bytes())
}

// GetPolicy reads a policy by name.
func (c *Client) GetPolicy(ctx context.Context, name string) (Policy, error) {
	body := xdrWriter{}
	body.u32(c.API)
	body.nullString(name)
	reply, err := c.call(ctx, getPolicy, body.bytes())
	if err != nil {
		return Policy{}, err
	}
	r, api, code, err := statusReader(reply)
	if err != nil {
		return Policy{}, err
	}
	if err := checkReplyAPI(api, c.API); err != nil {
		return Policy{}, err
	}
	if code != 0 {
		return Policy{}, operationError("GET_POLICY", code)
	}
	policy, err := readPolicy(&r, api)
	if err != nil {
		return Policy{}, err
	}
	if err := r.done(); err != nil {
		return Policy{}, err
	}
	return policy, nil
}

// ListPolicies returns policies matching expression.
func (c *Client) ListPolicies(ctx context.Context, expression string) ([]string, error) {
	body := xdrWriter{}
	body.u32(c.API)
	body.nullString(expression)
	reply, err := c.call(ctx, getPolicies, body.bytes())
	if err != nil {
		return nil, err
	}
	r, api, code, err := statusReader(reply)
	if err != nil {
		return nil, err
	}
	if err := checkReplyAPI(api, c.API); err != nil {
		return nil, err
	}
	if code != 0 {
		return nil, operationError("GET_POLS", code)
	}
	out, err := readStringList(&r, "policy")
	if err != nil {
		return nil, err
	}
	if err := r.done(); err != nil {
		return nil, err
	}
	return out, nil
}

// GetPrivs returns the MIT kadm5 authorization privilege bitmask.
func (c *Client) GetPrivs(ctx context.Context) (int32, error) {
	body := xdrWriter{}
	body.u32(c.API)
	reply, err := c.call(ctx, getPrivs, body.bytes())
	if err != nil {
		return 0, err
	}
	r, api, code, err := statusReader(reply)
	if err != nil {
		return 0, err
	}
	if err := checkReplyAPI(api, c.API); err != nil {
		return 0, err
	}
	if code != 0 {
		return 0, operationError("GET_PRIVS", code)
	}
	privs, err := r.i32()
	if err != nil {
		return 0, err
	}
	if err := r.done(); err != nil {
		return 0, err
	}
	return privs, nil
}

func statusReader(data []byte) (xdrReader, uint32, uint32, error) {
	r := xdrReader{b: data}
	api, err := r.u32()
	if err != nil {
		return r, 0, 0, err
	}
	code, err := r.u32()
	if err != nil {
		return r, 0, 0, err
	}
	return r, api, code, nil
}

func checkReplyAPI(api, expected uint32) error {
	if api != expected && api != APIv2 && api != APIv3 && api != APIv4 {
		return fmt.Errorf("kadm5: unsupported reply API %#x", api)
	}
	return nil
}

func readStringList(r *xdrReader, kind string) ([]string, error) {
	n, err := r.i32()
	if err != nil {
		return nil, err
	}
	if n < 0 || n > 1<<20 {
		return nil, fmt.Errorf("kadm5: invalid %s list count", kind)
	}
	arrayCount, err := r.u32()
	if err != nil {
		return nil, err
	}
	if arrayCount != uint32(n) {
		return nil, fmt.Errorf("kadm5: mismatched %s list counts", kind)
	}
	out := make([]string, 0, n)
	for i := int32(0); i < n; i++ {
		name, err := r.nullString()
		if err != nil {
			return nil, err
		}
		out = append(out, name)
	}
	return out, nil
}

func writePolicy(w *xdrWriter, policy Policy, api uint32) {
	w.nullString(policy.Name)
	w.i32(policy.MinLife)
	w.i32(policy.MaxLife)
	w.i32(policy.MinLength)
	w.i32(policy.MinClasses)
	w.i32(policy.HistoryNum)
	w.i32(0)
	if api >= APIv3 {
		w.u32(policy.MaxFailure)
		w.i32(policy.FailureCountInterval)
		w.i32(policy.LockoutDuration)
	}
	if api >= APIv4 {
		w.i32(policy.Attributes)
		w.i32(policy.MaxTicketLife)
		w.i32(policy.MaxRenewableLife)
		w.nullString("")
		w.i16(0)
		w.boolean(true)
	}
}

func readPolicy(r *xdrReader, api uint32) (Policy, error) {
	name, err := r.nullString()
	if err != nil {
		return Policy{}, err
	}
	minLife, err := r.i32()
	if err != nil {
		return Policy{}, err
	}
	maxLife, err := r.i32()
	if err != nil {
		return Policy{}, err
	}
	minLength, err := r.i32()
	if err != nil {
		return Policy{}, err
	}
	minClasses, err := r.i32()
	if err != nil {
		return Policy{}, err
	}
	history, err := r.i32()
	if err != nil {
		return Policy{}, err
	}
	if _, err := r.i32(); err != nil {
		return Policy{}, err
	}
	policy := Policy{Name: name, MinLife: minLife, MaxLife: maxLife,
		MinLength: minLength, MinClasses: minClasses, HistoryNum: history}
	if api >= APIv3 {
		maxFailure, err := r.u32()
		if err != nil {
			return Policy{}, err
		}
		interval, err := r.i32()
		if err != nil {
			return Policy{}, err
		}
		lockout, err := r.i32()
		if err != nil {
			return Policy{}, err
		}
		policy.MaxFailure = maxFailure
		policy.FailureCountInterval = interval
		policy.LockoutDuration = lockout
	}
	if api >= APIv4 {
		attrs, err := r.i32()
		if err != nil {
			return Policy{}, err
		}
		ticketLife, err := r.i32()
		if err != nil {
			return Policy{}, err
		}
		renewLife, err := r.i32()
		if err != nil {
			return Policy{}, err
		}
		if _, err := r.nullString(); err != nil {
			return Policy{}, err
		}
		if _, err := r.i16(); err != nil {
			return Policy{}, err
		}
		nullTL, err := r.boolean()
		if err != nil {
			return Policy{}, err
		}
		if !nullTL {
			more, err := r.boolean()
			if err != nil {
				return Policy{}, err
			}
			for more {
				if _, err := r.i16(); err != nil {
					return Policy{}, err
				}
				if _, err := r.opaque(); err != nil {
					return Policy{}, err
				}
				more, err = r.boolean()
				if err != nil {
					return Policy{}, err
				}
			}
		}
		policy.Attributes = attrs
		policy.MaxTicketLife = ticketLife
		policy.MaxRenewableLife = renewLife
	}
	return policy, nil
}
