package agent

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/QgMixtate/surveyscan/v2/contracts"
	"strings"

	"github.com/QgMixtate/surveyscan/v2/internal/platform/privatefile"
	"github.com/QgMixtate/surveyscan/v2/internal/remote/sshlinux"
)

// SSHTarget — безагентная цель, которую обслуживает эта «виртуальная» агентская личность (collector-host).
// Файлы секретов приватные (проверяет privatefile); сам конфиг цели секретов не содержит.
type SSHTarget struct {
	Addr           string `json:"addr"`
	User           string `json:"user"`
	HostKeySHA256  string `json:"host_key_sha256"`
	PasswordFile   string `json:"password_file,omitempty"`
	PrivateKeyFile string `json:"private_key_file,omitempty"`
	PassphraseFile string `json:"passphrase_file,omitempty"`
	// Secret — секрет из памяти (C51.03: collector получает учётку у центра по mTLS перед каждым сбором); файлы
	// тогда не используются. Не сериализуется.
	Secret func(context.Context) (sshlinux.Secret, error) `json:"-"`
	// Problem — код отказа для показа в Web (auth_failed, second_factor_required, unsupported_platform:…); не сериализуется
	Problem func(code string) `json:"-"`
}

// SSHProblem — фиксированный код отказа SSH-цели (без текста цели).
func SSHProblem(err error) string {
	var up *sshlinux.UnsupportedPlatform
	switch {
	case err == nil:
		return ""
	case errors.As(err, &up):
		return "unsupported_platform:" + up.OS
	case errors.Is(err, sshlinux.ErrSecondFactor):
		return "second_factor_required"
	case errors.Is(err, sshlinux.ErrAuth):
		return "auth_failed"
	case errors.Is(err, sshlinux.ErrHostKeyMismatch):
		return "host_key_changed"
	case errors.Is(err, sshlinux.ErrNetwork):
		return "host_unreachable"
	case errors.Is(err, sshlinux.ErrNoIdentity):
		return "command_failed"
	}
	return ""
}

func (t SSHTarget) problem(err error) {
	if t.Problem != nil {
		t.Problem(SSHProblem(err))
	}
}

// snapshot — 12 секций и кандидаты; без идентифицирующих кандидатов наблюдение не отправляется (иначе пустой актив).
func sshSnapshot(sections []contracts.Section) (Snapshot, error) {
	full := sshlinux.Complete12(sections)
	cands := sshlinux.Candidates(full)
	if len(cands) == 0 {
		return Snapshot{}, sshlinux.ErrNoIdentity
	}
	return Snapshot{Candidates: cands, Sections: full}, nil
}

// LoadSSHTarget читает приватный JSON цели и проверяет обязательные поля (ключ хоста обязателен).
func LoadSSHTarget(path string) (SSHTarget, error) {
	var t SSHTarget
	raw, err := privatefile.Read(path, 65536)
	if err != nil {
		return t, errors.New("ssh target config unavailable or not private")
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&t); err != nil {
		return t, errors.New("ssh target config invalid")
	}
	if t.Addr == "" || t.User == "" || !strings.HasPrefix(t.HostKeySHA256, "SHA256:") {
		return t, errors.New("ssh target requires addr, user and host_key_sha256")
	}
	if (t.PasswordFile == "") == (t.PrivateKeyFile == "") || (t.PasswordFile != "" && t.PassphraseFile != "") {
		return t, errors.New("ssh target requires exactly one of password_file or private_key_file")
	}
	return t, nil
}

func readSecretFile(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	b, err := privatefile.Read(path, 65536)
	if err != nil {
		return nil, errors.New("ssh secret file unavailable or not private")
	}
	return b, nil
}

// NewSSHCollect12 возвращает функцию сбора для runLoop12: каждый цикл читает секрет из приватного файла,
// собирает цель по SSH и приводит результат к 12 секциям. Ошибки не содержат секретов.
func NewSSHCollect12(t SSHTarget, policy sshlinux.Policy) func(context.Context) (Snapshot, error) {
	return func(ctx context.Context) (Snapshot, error) {
		if t.Secret != nil {
			secret, err := t.Secret(ctx)
			if err != nil {
				return Snapshot{}, errors.New("ssh credential unavailable from the center")
			}
			sections, err := sshlinux.Collect(ctx, sshlinux.Target{Addr: t.Addr, User: t.User, HostKeySHA256: t.HostKeySHA256}, secret, policy)
			if err != nil {
				t.problem(err)
				return Snapshot{}, err
			}
			snap, err := sshSnapshot(sections)
			t.problem(err)
			return snap, err
		}
		pw, err := readSecretFile(t.PasswordFile)
		if err != nil {
			return Snapshot{}, err
		}
		key, err := readSecretFile(t.PrivateKeyFile)
		if err != nil {
			return Snapshot{}, err
		}
		pp, err := readSecretFile(t.PassphraseFile)
		if err != nil {
			return Snapshot{}, err
		}
		secret := sshlinux.Secret{Password: strings.TrimRight(string(pw), "\r\n"), PrivateKeyPEM: key, Passphrase: strings.TrimRight(string(pp), "\r\n")}
		sections, err := sshlinux.Collect(ctx, sshlinux.Target{Addr: t.Addr, User: t.User, HostKeySHA256: t.HostKeySHA256}, secret, policy)
		if err != nil {
			return Snapshot{}, err // отмена/срок/сбой подключения: частичный результат не публикуем как свежий
		}
		return sshSnapshot(sections)
	}
}
