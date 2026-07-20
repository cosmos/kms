// Package pkcs11 implements a signing key backed by a PKCS#11 token or HSM.
// The private key never leaves the token: signing is performed on-device via the
// PKCS#11 C_Sign operation. Ed25519 (CKM_EDDSA) is the only key algorithm today;
// see algo.go for the per-algorithm seam.
package pkcs11

import (
	"fmt"
	"os"
	"strings"

	"github.com/cosmos/kms/config"
	"github.com/miekg/pkcs11"
)

// Config describes how to open a key on a PKCS#11 token. Exactly one of
// TokenLabel/Slot selects the token, at least one of KeyLabel/KeyID selects the
// key, and exactly one of PIN/PINEnv/PINFile supplies the user PIN. Algorithm
// defaults to "ed25519" when empty.
type Config struct {
	Module     string
	TokenLabel string
	Slot       *uint
	KeyLabel   string
	KeyID      []byte
	PIN        string
	PINEnv     string
	PINFile    string
	Algorithm  config.Algorithm
}

// selectSlot returns the slot to use: the explicit Slot when set, otherwise the
// slot whose token CKA_LABEL matches TokenLabel.
func selectSlot(mod *pkcs11.Ctx, cfg Config) (uint, error) {
	if cfg.Slot != nil {
		return *cfg.Slot, nil
	}
	slots, err := mod.GetSlotList(true)
	if err != nil {
		return 0, fmt.Errorf("pkcs11: list slots: %w", err)
	}
	for _, slot := range slots {
		info, err := mod.GetTokenInfo(slot)
		if err != nil {
			continue
		}
		// Token labels are space-padded to 32 bytes by the spec.
		if strings.TrimRight(info.Label, " ") == cfg.TokenLabel {
			return slot, nil
		}
	}
	return 0, fmt.Errorf("pkcs11: no token with label %q", cfg.TokenLabel)
}

// findObject locates exactly one key object of the given class matching the
// configured label and/or id.
func findObject(mod *pkcs11.Ctx, session pkcs11.SessionHandle, class uint, cfg Config) (pkcs11.ObjectHandle, error) {
	template := []*pkcs11.Attribute{pkcs11.NewAttribute(pkcs11.CKA_CLASS, class)}
	if cfg.KeyLabel != "" {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_LABEL, cfg.KeyLabel))
	}
	if len(cfg.KeyID) > 0 {
		template = append(template, pkcs11.NewAttribute(pkcs11.CKA_ID, cfg.KeyID))
	}

	if err := mod.FindObjectsInit(session, template); err != nil {
		return 0, err
	}
	handles, _, err := mod.FindObjects(session, 2)
	if finErr := mod.FindObjectsFinal(session); finErr != nil && err == nil {
		err = finErr
	}
	if err != nil {
		return 0, err
	}
	switch {
	case len(handles) == 0:
		return 0, fmt.Errorf("no object matching %s", keySelector(cfg))
	case len(handles) > 1:
		return 0, fmt.Errorf("multiple objects match %s: refine key_label/key_id", keySelector(cfg))
	}
	return handles[0], nil
}

// keySelector describes the configured key search criteria for error messages.
func keySelector(cfg Config) string {
	switch {
	case cfg.KeyLabel != "" && len(cfg.KeyID) > 0:
		return fmt.Sprintf("key_label=%q key_id=%x", cfg.KeyLabel, cfg.KeyID)
	case cfg.KeyLabel != "":
		return fmt.Sprintf("key_label=%q", cfg.KeyLabel)
	default:
		return fmt.Sprintf("key_id=%x", cfg.KeyID)
	}
}

// resolvePIN returns the user PIN from whichever source the config specifies.
// The PIN is read at open time (not stored in config files): an env var is read
// from the process environment; a file is read and stripped of trailing
// whitespace. An empty resolved PIN is an error.
func resolvePIN(cfg Config) (string, error) {
	switch {
	case cfg.PIN != "":
		return cfg.PIN, nil
	case cfg.PINEnv != "":
		v := os.Getenv(cfg.PINEnv)
		if v == "" {
			return "", fmt.Errorf("pkcs11: pin_env %q is empty or unset", cfg.PINEnv)
		}
		return v, nil
	case cfg.PINFile != "":
		raw, err := os.ReadFile(cfg.PINFile)
		if err != nil {
			return "", fmt.Errorf("pkcs11: read pin_file %q: %w", cfg.PINFile, err)
		}
		v := strings.TrimRight(string(raw), " \t\r\n")
		if v == "" {
			return "", fmt.Errorf("pkcs11: pin_file %q is empty", cfg.PINFile)
		}
		return v, nil
	default:
		return "", fmt.Errorf("pkcs11: no PIN source configured (set pin, pin_env, or pin_file)")
	}
}
