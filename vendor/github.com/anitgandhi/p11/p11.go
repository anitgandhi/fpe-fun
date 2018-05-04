// package p11 provides cryptographic algorithm implementations
// that meet the interfaces found in the crypto standard library,
// but are backed by an HSM.
// This provides an easy plug-and-play abstraction for common
// crypto operations.
// inspired by github.com/letsencrypt/pkcs11key

package p11

import (
	"github.com/miekg/pkcs11"
)

type Context struct {
	HSM *pkcs11.Ctx

	// TODO: make this a concurrent-safe pool of sessions, default of size 1
	Session pkcs11.SessionHandle
}

// TODO: make these an Options struct?
func New(lib string, pin string, sessionPoolSize int) (*Context, error) {
	ctx := Context{}

	ctx.HSM = pkcs11.New(lib)

	err := ctx.HSM.Initialize()
	if err != nil {
		return nil, err
	}

	// TODO: add way to specify slot rather than always using the first one
	slots, err := ctx.HSM.GetSlotList(true)
	if err != nil {
		return nil, err
	}

	// TODO: make the session read/write a choice?
	ctx.Session, err = ctx.HSM.OpenSession(slots[0], pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return nil, err
	}

	err = ctx.HSM.Login(ctx.Session, pkcs11.CKU_USER, pin)
	if err != nil {
		return nil, err
	}

	return &ctx, nil
}

// Destroy tears down the HSM session and context
func (c *Context) Destroy() {
	// Log out of and close all sessions
	c.HSM.Logout(c.Session)
	c.HSM.CloseSession(c.Session)

	// Global Cleanup
	c.HSM.Finalize()
	c.HSM.Destroy()
}

func (c *Context) GetSession() pkcs11.SessionHandle {
	return c.Session
}

// func (c *Context) PutSession(pkcs11.SessionHandle) {

// }

// Useful helper functions

// FindObjectByID searches for a session or token object by CKA_ID and returns the object handle
func (c *Context) FindObjectByID(id string) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	}

	var ret pkcs11.ObjectHandle
	var err error

	err = c.HSM.FindObjectsInit(c.Session, template)
	if err != nil {
		return ret, err
	}

	oids, _, err := c.HSM.FindObjects(c.Session, 1)
	if err != nil {
		return ret, err
	}

	err = c.HSM.FindObjectsFinal(c.Session)
	if err != nil {
		return ret, err
	}

	ret = oids[0]

	return ret, nil
}

// FindObjectByLabel searches for a token object by CKA_LABEL and returns the object handle
func (c *Context) FindObjectByLabel(label string) (pkcs11.ObjectHandle, error) {

	return 0, nil
}

// FindObjectByTemplate searches for a token object by the attribute template and returns the object handle
func (c *Context) FindObjectByTemplate(template []*pkcs11.Attribute) (pkcs11.ObjectHandle, error) {
	return 0, nil
}
