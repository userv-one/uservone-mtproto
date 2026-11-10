package core

import (
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

type rotatingUsers struct {
	mu         sync.RWMutex
	current    []user
	previous   []user
	previousTo time.Time
	now        func() time.Time
}

func newRotatingUsers(users []user) *rotatingUsers {
	return &rotatingUsers{current: users, now: time.Now}
}

func (u *rotatingUsers) snapshot() []user {
	u.mu.RLock()
	defer u.mu.RUnlock()
	result := append([]user(nil), u.current...)
	if !u.now().Before(u.previousTo) {
		return result
	}
	seen := make(map[string]struct{}, len(result))
	for _, account := range result {
		seen[account.name+"\x00"+string(account.secret)] = struct{}{}
	}
	for _, account := range u.previous {
		key := account.name + "\x00" + string(account.secret)
		if _, found := seen[key]; !found {
			result = append(result, account)
		}
	}
	return result
}

func (u *rotatingUsers) currentUsers() []user {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return append([]user(nil), u.current...)
}

func (u *rotatingUsers) rotate(users []user, grace time.Duration) {
	u.mu.Lock()
	u.previous = u.current
	u.current = users
	u.previousTo = u.now().Add(grace)
	if grace <= 0 {
		u.previous = nil
	}
	u.mu.Unlock()
}

// ReloadUsers activates new secrets and keeps the previous set during grace.
func (p *Proxy) ReloadUsers(users map[string]string, grace time.Duration) error {
	if grace < 0 {
		return errors.New("rotation grace period cannot be negative")
	}
	cfg := p.config
	cfg.Users = users
	if err := cfg.Validate(); err != nil {
		return err
	}
	rotated := make([]user, 0, len(users))
	for name, encodedSecret := range users {
		secret, _ := hex.DecodeString(encodedSecret)
		rotated = append(rotated, user{name: name, secret: secret})
	}
	p.users.rotate(rotated, grace)
	return nil
}
