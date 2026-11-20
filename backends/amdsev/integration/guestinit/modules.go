package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// modulesInOrder lists the kit's modules in dir in load order: guest-image.sh
// names each <n>-<module>.ko.zst, n counting from 1 in the order pins.sh
// gives, so a module loads after what it depends on.
func modulesInOrder(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("modules: %w", err)
	}
	type mod struct {
		n    int
		path string
	}
	var mods []mod
	for _, e := range entries {
		num, _, ok := strings.Cut(e.Name(), "-")
		n, err := strconv.Atoi(num)
		if !ok || err != nil || n <= 0 || e.IsDir() {
			return nil, fmt.Errorf("modules: %s is not named <n>-<module>", e.Name())
		}
		mods = append(mods, mod{n, filepath.Join(dir, e.Name())})
	}
	if len(mods) == 0 {
		return nil, fmt.Errorf("modules: %s is empty; the guest needs the sev-guest driver", dir)
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].n < mods[j].n })
	out := make([]string, len(mods))
	for i, m := range mods {
		if m.n != i+1 {
			return nil, fmt.Errorf("modules: no module %d before %s", i+1, filepath.Base(m.path))
		}
		out[i] = m.path
	}
	return out, nil
}
