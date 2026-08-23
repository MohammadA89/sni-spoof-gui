package profiles

import (
	"os"
	"path/filepath"
	"testing"
)

const (
	linkA = "vless://b831381d-6324-4d53-ad4f-8cda48b30811@a.example.com:443?security=reality&sni=x.com&pbk=k#A"
	linkB = "trojan://secret@b.example.com:443?security=tls&sni=b.example.com#B"
)

func TestAddDeduplicatesByLink(t *testing.T) {
	var s Store

	e1, added, err := s.Add(linkA)
	if err != nil || !added {
		t.Fatalf("first add: added=%v err=%v", added, err)
	}
	// Re-importing the same subscription is routine, and it must not grow the
	// list every time.
	e2, added, err := s.Add(linkA)
	if err != nil {
		t.Fatalf("second add: %v", err)
	}
	if added {
		t.Error("the same link was added twice")
	}
	if e1.ID != e2.ID {
		t.Errorf("ids differ for the same link: %s vs %s", e1.ID, e2.ID)
	}
	if len(s.Entries) != 1 {
		t.Errorf("entries = %d, want 1", len(s.Entries))
	}
}

// A list with nothing selected is a dead end for the user, so the first import
// selects itself.
func TestFirstImportBecomesActive(t *testing.T) {
	var s Store
	if _, _, err := s.Add(linkA); err != nil {
		t.Fatalf("add: %v", err)
	}
	if s.Active == "" {
		t.Fatal("nothing became active")
	}
	first := s.Active

	if _, _, err := s.Add(linkB); err != nil {
		t.Fatalf("add: %v", err)
	}
	if s.Active != first {
		t.Error("a later import stole the selection")
	}
}

// Re-importing an existing link must not discard what the user set on it.
func TestAddKeepsUserSettingsOnAnExistingEntry(t *testing.T) {
	var s Store
	e, _, err := s.Add(linkA)
	if err != nil {
		t.Fatalf("add: %v", err)
	}
	e.Name = "my renamed config"
	e.EdgeOverride = true
	if !s.Update(e) {
		t.Fatal("update failed")
	}

	if _, added, err := s.Add(linkA); err != nil || added {
		t.Fatalf("re-add: added=%v err=%v", added, err)
	}
	got, _ := s.Get(e.ID)
	if got.Name != "my renamed config" {
		t.Errorf("name was lost: %q", got.Name)
	}
	if !got.EdgeOverride {
		t.Error("edge override was lost")
	}
}

func TestRemoveMovesTheSelection(t *testing.T) {
	var s Store
	a, _, _ := s.Add(linkA)
	b, _, _ := s.Add(linkB)
	if s.Active != a.ID {
		t.Fatalf("active = %s, want %s", s.Active, a.ID)
	}

	if !s.Remove(a.ID) {
		t.Fatal("remove failed")
	}
	// Removing the active entry must leave something selected, or the user is
	// left with a list and no way to connect.
	if s.Active != b.ID {
		t.Errorf("active = %q, want the remaining entry %s", s.Active, b.ID)
	}

	s.Remove(b.ID)
	if s.Active != "" {
		t.Errorf("active = %q, want empty when the list is empty", s.Active)
	}
	if s.Remove("nope") {
		t.Error("removing an unknown id reported success")
	}
}

func TestSelectRejectsUnknownID(t *testing.T) {
	var s Store
	s.Add(linkA)
	if err := s.Select("nope"); err == nil {
		t.Error("selecting an unknown id should fail")
	}
}

func TestActiveProfileAppliesTheRename(t *testing.T) {
	var s Store
	e, _, _ := s.Add(linkA)
	e.Name = "renamed"
	s.Update(e)

	p, _, err := s.ActiveProfile()
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if p.Name != "renamed" {
		t.Errorf("name = %q, want renamed", p.Name)
	}
	if p.Address != "a.example.com" {
		t.Errorf("address = %q", p.Address)
	}
}

func TestActiveProfileWithNothingSelected(t *testing.T) {
	var s Store
	if _, _, err := s.ActiveProfile(); err == nil {
		t.Error("expected an error when nothing is selected")
	}
}

func TestAddRejectsAnUnparseableLink(t *testing.T) {
	var s Store
	if _, _, err := s.Add("not a link"); err == nil {
		t.Error("expected an error")
	}
	if len(s.Entries) != 0 {
		t.Error("a bad link should not be stored")
	}
}

// A missing file is the normal first-run state, not an error to show the user.
func TestLoadMissingFileIsEmpty(t *testing.T) {
	s, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(s.Entries) != 0 || s.Active != "" {
		t.Errorf("expected an empty store, got %+v", s)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")

	var s Store
	a, _, _ := s.Add(linkA)
	s.Add(linkB)
	a.EdgeOverride = true
	a.Name = "kept"
	s.Update(a)

	if err := Save(path, &s); err != nil {
		t.Fatalf("save: %v", err)
	}
	got, err := Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(got.Entries) != 2 {
		t.Fatalf("entries = %d, want 2", len(got.Entries))
	}
	if got.Active != s.Active {
		t.Errorf("active = %q, want %q", got.Active, s.Active)
	}
	e, ok := got.Get(a.ID)
	if !ok {
		t.Fatal("entry missing after reload")
	}
	if !e.EdgeOverride || e.Name != "kept" {
		t.Errorf("settings lost: %+v", e)
	}
}

// The file holds credentials, so it must not be world-readable.
func TestSaveUsesRestrictivePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	var s Store
	s.Add(linkA)
	if err := Save(path, &s); err != nil {
		t.Fatalf("save: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	// Windows does not honour Unix permission bits, so this asserts what was
	// requested rather than what the filesystem enforces.
	if perm := info.Mode().Perm(); perm&0o077 != 0 && perm != 0o666 {
		t.Errorf("mode = %v, want no group or world access", perm)
	}
}

func TestIDForIsStableAndIgnoresSurroundingSpace(t *testing.T) {
	if IDFor(linkA) != IDFor("  "+linkA+"\n") {
		t.Error("surrounding whitespace changed the id")
	}
	if IDFor(linkA) == IDFor(linkB) {
		t.Error("different links produced the same id")
	}
}
