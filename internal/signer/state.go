package signer

import (
	"fmt"
	"os"

	cmtjson "github.com/cometbft/cometbft/libs/json"
	"github.com/cometbft/cometbft/privval"
)

// InitState writes a sign-state file recording the double-sign floor: kms
// refuses to sign at or below height/round/step. height 0 is the "new
// validator, never signed" marker. An existing non-empty file is never
// overwritten — delete it manually if that is really intended.
func InitState(stateFile string, height int64, round int32, step int8) error {
	if height < 0 || round < 0 || step < 0 || step > 3 {
		return fmt.Errorf("invalid sign state height=%d round=%d step=%d (step must be 0..3)", height, round, step)
	}
	if raw, err := os.ReadFile(stateFile); err == nil && len(raw) > 0 {
		return fmt.Errorf("sign-state file %s already exists; refusing to overwrite a double-sign floor", stateFile)
	}
	st := privval.FilePVLastSignState{Height: height, Round: round, Step: step}
	raw, err := cmtjson.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(stateFile, raw, 0o600)
}
