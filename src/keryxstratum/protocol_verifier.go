package keryxstratum

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

type verifierResult struct {
	OK            bool     `json:"ok"`
	Error         string   `json:"error"`
	Pubkey        string   `json:"pubkey"`
	Identity      string   `json:"identity"`
	Model         string   `json:"model"`
	Tier          uint32   `json:"tier"`
	FinalState    uint64   `json:"final_state"`
	PowLE         string   `json:"pow_le"`
	Payload       string   `json:"payload"`
	Payloads      []string `json:"payloads"`
	AttentionRoot string   `json:"attention_root"`
	Prompt        string   `json:"prompt"`
	PromptLen     uint32   `json:"prompt_len"`
	MaxTokens     uint32   `json:"max_tokens"`
	Reward        string   `json:"reward"`
	Models        []struct {
		Tier  uint32 `json:"tier"`
		Model string `json:"model"`
	} `json:"models"`
}

// The helper loads only the configured escrow key; it never returns that key.
// A failed/ambiguous helper call leaves the bridge closed to new mining work.
type protocolVerifier struct {
	mu       sync.Mutex
	slots    chan struct{}
	cmd      *exec.Cmd
	in       io.WriteCloser
	out      *bufio.Reader
	identity verifierResult
	failed   bool
}

func newProtocolVerifier(cfg BridgeConfig) (*protocolVerifier, error) {
	if !filepath.IsAbs(cfg.VerifierBinary) {
		return nil, fmt.Errorf("verifier_binary must be an absolute path")
	}
	binaryPath, err := exec.LookPath(cfg.VerifierBinary)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve verifier executable")
	}
	if cfg.VerifierSHA256 != "" {
		f, err := os.Open(binaryPath)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		h := sha256.New()
		if _, err = io.Copy(h, f); err != nil {
			return nil, err
		}
		if hex.EncodeToString(h.Sum(nil)) != cfg.VerifierSHA256 {
			return nil, fmt.Errorf("verifier SHA256 mismatch")
		}
	}
	v := &protocolVerifier{slots: make(chan struct{}, 8)}
	v.cmd = exec.Command(binaryPath)
	hideVerifierWindow(v.cmd)
	v.in, err = v.cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	pipe, err := v.cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	v.out = bufio.NewReaderSize(pipe, 64*1024)
	if err = v.cmd.Start(); err != nil {
		return nil, err
	}
	v.identity, err = v.call(map[string]any{"op": "init", "network": cfg.Network, "payout": cfg.PayoutAddress, "cert": cfg.EscrowCert, "key_file": cfg.EscrowKeyFile})
	if err != nil {
		v.Close()
		return nil, err
	}
	return v, nil
}

func (v *protocolVerifier) Close() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.closeLocked()
}
func (v *protocolVerifier) closeLocked() {
	if v.failed {
		return
	}
	v.failed = true
	if v.in != nil {
		v.in.Close()
	}
	if v.cmd != nil && v.cmd.Process != nil {
		v.cmd.Process.Kill()
		v.cmd.Wait()
	}
}
func (v *protocolVerifier) healthy() bool { v.mu.Lock(); defer v.mu.Unlock(); return !v.failed }

func (v *protocolVerifier) call(request any) (verifierResult, error) {
	select {
	case v.slots <- struct{}{}:
		defer func() { <-v.slots }()
	default:
		return verifierResult{}, fmt.Errorf("verifier busy")
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.failed {
		return verifierResult{}, fmt.Errorf("verifier unavailable; operator restart required")
	}
	raw, err := json.Marshal(request)
	if err != nil {
		return verifierResult{}, err
	}
	if len(raw) > 6*1024*1024-1 {
		return verifierResult{}, fmt.Errorf("verifier request too large")
	}
	type result struct {
		value verifierResult
		err   error
	}
	done := make(chan result, 1)
	go func() {
		r := result{}
		if _, r.err = v.in.Write(append(raw, '\n')); r.err == nil {
			line, err := readBoundedLine(v.out, 6*1024*1024)
			r.err = err
			if err == nil {
				r.err = json.Unmarshal(line, &r.value)
			}
		}
		done <- r
	}()
	select {
	case r := <-done:
		if r.err != nil {
			v.closeLocked()
			return verifierResult{}, fmt.Errorf("verifier transport failed")
		}
		if !r.value.OK {
			return r.value, fmt.Errorf("verifier: %s", r.value.Error)
		}
		return r.value, nil
	case <-time.After(30 * time.Second):
		v.closeLocked()
		<-done
		return verifierResult{}, fmt.Errorf("verifier timeout; operator restart required")
	}
}

func readBoundedLine(reader *bufio.Reader, limit int) ([]byte, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		if len(line)+len(chunk) > limit {
			return nil, fmt.Errorf("line limit exceeded")
		}
		line = append(line, chunk...)
		if err == nil {
			return line, nil
		}
		if err != bufio.ErrBufferFull {
			return nil, err
		}
	}
}
