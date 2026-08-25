package baseline

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// Store persists baseline files in a directory, one per group, as JSON.
//
// File layout:
//
//   <dir>/<safe-group>.json    { "file": any, "exec": any, "net": any, "frozen": bool }
//
// Save and Load are atomic per group (write to tmp, rename). SaveAll walks
// the in-memory index and writes one file per group.
type Store struct {
	dir string
	mu  sync.Mutex // serialize file writes
}

// NewStore constructs a Store rooted at dir (created if missing).
func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create baseline dir: %w", err)
	}
	return &Store{dir: dir}, nil
}

// GroupFile is one group's persisted baseline.
type GroupFile struct {
	File   any `json:"file,omitempty"`
	Exec   any `json:"exec,omitempty"`
	Net    any `json:"net,omitempty"`
	Frozen bool `json:"frozen"`
}

// Load reads a group's persisted state from <dir>/<safe>.json.
// Returns (nil, nil) if the file doesn't exist (cold start).
func (s *Store) Load(group string) (*GroupFile, error) {
	path := s.path(group)
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	if len(data) == 0 {
		return nil, nil
	}
	var out GroupFile
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return &out, nil
}

// Save writes group's persisted state to <dir>/<safe>.json atomically.
func (s *Store) Save(group string, gf *GroupFile) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(group, gf)
}

func (s *Store) saveLocked(group string, gf *GroupFile) error {
	path := s.path(group)
	tmp := path + ".tmp"
	data, err := json.Marshal(gf)
	if err != nil {
		return err
	}
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// List returns all groups with a persisted baseline file on disk.
func (s *Store) List() ([]string, error) {
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if filepath.Ext(name) != ".json" {
			continue
		}
		out = append(out, name[:len(name)-len(".json")])
	}
	return out, nil
}

// PathFor returns the on-disk path for a group. Useful for ops like
// /baseline/{group}/reset that want to delete the file directly.
func (s *Store) PathFor(group string) string { return s.path(group) }

func (s *Store) path(group string) string {
	// Group key may contain "/"; flatten to "_" so it's a single file.
	safe := make([]byte, 0, len(group))
	for i := 0; i < len(group); i++ {
		c := group[i]
		switch c {
		case '/', ':', '=', ' ':
			safe = append(safe, '_')
		default:
			safe = append(safe, c)
		}
	}
	return filepath.Join(s.dir, string(safe)+".json")
}
