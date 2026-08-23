//go:build windows

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/patterniha-advance/sni-spoofing-advance/internal/profiles"
	"github.com/patterniha-advance/sni-spoofing-advance/internal/share"
)

// ProfileView is one row of the config list, shaped for the UI rather than for
// storage. It deliberately carries no UUID or password: this crosses into the
// frontend, where it would end up in a devtools console or a screenshot.
type ProfileView struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	Endpoint string `json:"endpoint"`
	Security string `json:"security"`
	Network  string `json:"network"`
	SNI      string `json:"sni"`

	Active       bool `json:"active"`
	EdgeOverride bool `json:"edgeOverride"`

	// Warnings are the import-time notes: what was dropped, and what will stop
	// this config from running. Usable is false when it cannot run at all.
	Warnings []string `json:"warnings"`
	Usable   bool     `json:"usable"`
	Problem  string   `json:"problem,omitempty"`
}

// ImportResult reports what a paste produced.
type ImportResult struct {
	Added int `json:"added"`
	// Existing counts links that were already in the list. Importing the same
	// subscription twice is normal, and it should read as "nothing new" rather
	// than as a failure.
	Existing int      `json:"existing"`
	Failed   []string `json:"failed"`
}

// profilesPath puts the config list next to the executable, like config.json.
func (a *App) profilesPath() string {
	return filepath.Join(filepath.Dir(a.configPath), "profiles.json")
}

// loadProfiles reads the store once and caches it on the App.
func (a *App) loadProfiles() *profiles.Store {
	a.mu.Lock()
	cached := a.store
	a.mu.Unlock()
	if cached != nil {
		return cached
	}

	// Read outside the lock: a.log takes it, and holding it across a file read
	// would also block every stats push.
	s, err := profiles.Load(a.profilesPath())
	if err != nil {
		a.log("could not read the config list: %v", err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()
	// Another caller may have loaded it while the file was being read; keep
	// whichever landed first so callers never hold two different stores.
	if a.store == nil {
		a.store = s
	}
	return a.store
}

// saveProfiles persists the store.
func (a *App) saveProfiles() error {
	a.mu.Lock()
	s := a.store
	a.mu.Unlock()
	if s == nil {
		return nil
	}
	return profiles.Save(a.profilesPath(), s)
}

// ImportConfigs adds one or more share links, or a subscription body.
//
// A single bad line does not fail the import: a subscription with one broken
// entry should still give the user the other forty, with the failures named.
func (a *App) ImportConfigs(text string) (ImportResult, error) {
	var res ImportResult
	if strings.TrimSpace(text) == "" {
		return res, fmt.Errorf("paste a config link or a subscription body first")
	}

	store := a.loadProfiles()

	parsed, parseErrs := share.ParseMany(text)
	for _, pe := range parseErrs {
		res.Failed = append(res.Failed, pe.Error())
	}

	a.mu.Lock()
	for _, p := range parsed {
		_, added, err := store.Add(p.Raw)
		if err != nil {
			res.Failed = append(res.Failed, err.Error())
			continue
		}
		if added {
			res.Added++
		} else {
			res.Existing++
		}
	}
	a.mu.Unlock()

	if res.Added == 0 && res.Existing == 0 {
		if len(res.Failed) > 0 {
			return res, fmt.Errorf("nothing could be imported: %s", res.Failed[0])
		}
		return res, fmt.Errorf("no config links found in that text")
	}

	if err := a.saveProfiles(); err != nil {
		return res, err
	}
	// Redacted, because the log view is one screenshot away from a support
	// thread and these links carry credentials.
	for _, p := range parsed {
		a.log("imported %s", p.Redacted())
	}
	if len(res.Failed) > 0 {
		a.log("%d entries could not be read", len(res.Failed))
	}
	return res, nil
}

// ListProfiles returns the config list for the UI.
func (a *App) ListProfiles() []ProfileView {
	store := a.loadProfiles()

	a.mu.Lock()
	entries := make([]profiles.Entry, len(store.Entries))
	copy(entries, store.Entries)
	active := store.Active
	a.mu.Unlock()

	out := make([]ProfileView, 0, len(entries))
	for _, e := range entries {
		v := ProfileView{ID: e.ID, Active: e.ID == active, EdgeOverride: e.EdgeOverride}

		p, err := share.ParseLink(e.Link)
		if err != nil {
			// A stored link that no longer parses still gets a row, or it
			// becomes invisible and unremovable.
			v.Name = e.Name
			if v.Name == "" {
				v.Name = "unreadable config"
			}
			v.Problem = err.Error()
			out = append(out, v)
			continue
		}
		if e.Name != "" {
			p.Name = e.Name
		}

		v.Name = p.Label()
		v.Protocol = p.Protocol
		v.Endpoint = p.Endpoint()
		v.Security = p.Security
		v.Network = p.Network
		v.SNI = p.SNI
		v.Warnings = p.Warnings
		if err := p.Validate(); err != nil {
			v.Problem = err.Error()
		} else {
			v.Usable = true
		}
		out = append(out, v)
	}
	return out
}

// SelectProfile makes a config the active one.
func (a *App) SelectProfile(id string) error {
	store := a.loadProfiles()

	a.mu.Lock()
	err := store.Select(id)
	running := a.client != nil
	a.mu.Unlock()
	if err != nil {
		return err
	}
	if err := a.saveProfiles(); err != nil {
		return err
	}

	if p, _, perr := store.ActiveProfile(); perr == nil {
		a.log("selected %s", p.Redacted())
	}
	if running {
		a.log("reconnect for the new config to take effect")
	}
	return nil
}

// DeleteProfile removes a config from the list.
func (a *App) DeleteProfile(id string) error {
	store := a.loadProfiles()

	a.mu.Lock()
	ok := store.Remove(id)
	a.mu.Unlock()
	if !ok {
		return fmt.Errorf("no config with id %s", id)
	}
	if err := a.saveProfiles(); err != nil {
		return err
	}
	a.log("removed a config from the list")
	return nil
}

// RenameProfile sets a display name, or clears it when name is empty.
func (a *App) RenameProfile(id, name string) error {
	return a.updateEntry(id, func(e *profiles.Entry) {
		e.Name = strings.TrimSpace(name)
	})
}

// SetEdgeOverride turns the Cloudflare-fronted dialling mode on or off for one
// config: the connection goes to a scanned clean edge while the config's own
// SNI travels unchanged.
func (a *App) SetEdgeOverride(id string, on bool) error {
	if err := a.updateEntry(id, func(e *profiles.Entry) { e.EdgeOverride = on }); err != nil {
		return err
	}
	if on {
		a.log("this config will be dialled at the scanned edge address")
	} else {
		a.log("this config will be dialled at its own address")
	}
	return nil
}

func (a *App) updateEntry(id string, mutate func(*profiles.Entry)) error {
	store := a.loadProfiles()

	a.mu.Lock()
	e, ok := store.Get(id)
	if ok {
		mutate(&e)
		store.Update(e)
	}
	a.mu.Unlock()

	if !ok {
		return fmt.Errorf("no config with id %s", id)
	}
	return a.saveProfiles()
}

// ActiveProfileJSON returns the xray configuration the current selection would
// produce. It is a diagnostic: when a config will not start, this is what to
// look at, and it is far more useful than a log line.
func (a *App) ActiveProfileJSON() (string, error) {
	store := a.loadProfiles()
	p, _, err := store.ActiveProfile()
	if err != nil {
		return "", err
	}
	blob, err := p.JSON("proxy")
	if err != nil {
		return "", err
	}
	return string(blob), nil
}
