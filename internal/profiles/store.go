// Package profiles persists the imported server list.
//
// Entries hold the original share link rather than a decomposed profile. Two
// things follow from that, and both are the reason for it: the on-disk format
// cannot drift out of step with the parser, and a parser fix applies to every
// config the user already imported instead of only to the next one.
package profiles

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/patterniha-advance/sni-spoofing-advance/internal/share"
)

// Entry is one stored server.
type Entry struct {
	ID   string `json:"id"`
	Link string `json:"link"`

	// Name overrides the link's own label when the user renames an entry.
	Name string `json:"name,omitempty"`

	// EdgeOverride dials the scanned clean edge instead of the address the
	// link names, keeping the config's own SNI. It is the Cloudflare-fronted
	// case, and it is per entry because only some configs are behind a CDN.
	EdgeOverride bool `json:"edge_override,omitempty"`
}

// Store is the whole persisted list.
type Store struct {
	Active  string  `json:"active"`
	Entries []Entry `json:"entries"`
}

// IDFor derives an entry's identifier from the link itself, so importing the
// same config twice updates one entry rather than creating a second identical
// one.
func IDFor(link string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(link)))
	return hex.EncodeToString(sum[:8])
}

// Add parses and stores a link, returning the entry and whether it was new.
// The first entry imported becomes the active one, because a list with nothing
// selected is a dead end for the user.
func (s *Store) Add(link string) (Entry, bool, error) {
	p, err := share.ParseLink(link)
	if err != nil {
		return Entry{}, false, err
	}

	e := Entry{ID: IDFor(p.Raw), Link: p.Raw}
	for i, existing := range s.Entries {
		if existing.ID == e.ID {
			// Keep whatever the user set on the existing entry; the link is
			// identical, so there is nothing else to update.
			return s.Entries[i], false, nil
		}
	}

	s.Entries = append(s.Entries, e)
	if s.Active == "" {
		s.Active = e.ID
	}
	return e, true, nil
}

// Remove deletes an entry. Removing the active one moves the selection to the
// first remaining entry rather than leaving nothing selected.
func (s *Store) Remove(id string) bool {
	for i, e := range s.Entries {
		if e.ID != id {
			continue
		}
		s.Entries = append(s.Entries[:i], s.Entries[i+1:]...)
		if s.Active == id {
			s.Active = ""
			if len(s.Entries) > 0 {
				s.Active = s.Entries[0].ID
			}
		}
		return true
	}
	return false
}

// Get returns an entry by ID.
func (s *Store) Get(id string) (Entry, bool) {
	for _, e := range s.Entries {
		if e.ID == id {
			return e, true
		}
	}
	return Entry{}, false
}

// Update replaces an entry in place.
func (s *Store) Update(e Entry) bool {
	for i, existing := range s.Entries {
		if existing.ID == e.ID {
			s.Entries[i] = e
			return true
		}
	}
	return false
}

// Select makes id the active entry.
func (s *Store) Select(id string) error {
	if _, ok := s.Get(id); !ok {
		return fmt.Errorf("profiles: no config with id %s", id)
	}
	s.Active = id
	return nil
}

// ActiveEntry returns the selected entry.
func (s *Store) ActiveEntry() (Entry, bool) {
	if s.Active == "" {
		return Entry{}, false
	}
	return s.Get(s.Active)
}

// ActiveProfile parses the selected entry.
func (s *Store) ActiveProfile() (*share.Profile, Entry, error) {
	e, ok := s.ActiveEntry()
	if !ok {
		return nil, Entry{}, fmt.Errorf("profiles: no config selected")
	}
	p, err := share.ParseLink(e.Link)
	if err != nil {
		return nil, e, fmt.Errorf("profiles: the selected config no longer parses: %w", err)
	}
	if e.Name != "" {
		p.Name = e.Name
	}
	return p, e, nil
}

// Load reads the store, returning an empty one when the file does not exist.
// A missing list is the normal first-run state, not an error.
func Load(path string) (*Store, error) {
	s := &Store{}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return s, nil
		}
		return s, fmt.Errorf("profiles: read %s: %w", path, err)
	}
	if err := json.Unmarshal(data, s); err != nil {
		return &Store{}, fmt.Errorf("profiles: parse %s: %w", path, err)
	}
	return s, nil
}

// Save writes the store atomically. The file holds credentials, so it is
// written 0600 rather than the 0644 a config file would get.
func Save(path string, s *Store) error {
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return fmt.Errorf("profiles: encode: %w", err)
	}
	data = append(data, '\n')

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("profiles: create directory: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("profiles: write temp file: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("profiles: replace %s: %w", path, err)
	}
	return nil
}
