// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Bijstaan

package client

import "testing"

// The server renders "no packages" as an empty JSON array, because that is what
// PHP does with an empty associative array. Decoding it must not fail: a strict
// map here broke every no-op check-in.
func TestPackageSetAcceptsEmptyArray(t *testing.T) {
	for _, body := range []string{`[]`, `null`, `{}`, ``} {
		var set PackageSet
		if body != `` {
			if err := set.UnmarshalJSON([]byte(body)); err != nil {
				t.Fatalf("body %q: unexpected error %v", body, err)
			}
		} else {
			if err := set.UnmarshalJSON([]byte(``)); err != nil {
				t.Fatalf("empty body: unexpected error %v", err)
			}
		}
		if len(set) != 0 {
			t.Fatalf("body %q: expected no packages, got %d", body, len(set))
		}
	}
}

func TestPackageSetDecodesPackages(t *testing.T) {
	var set PackageSet
	err := set.UnmarshalJSON([]byte(`{"agent":{"version":"1.2.3","url":"https://x/y","sha256":"abc","size":42}}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	pkg, ok := set["agent"]
	if !ok {
		t.Fatal("agent package missing")
	}
	if pkg.Version != "1.2.3" || pkg.Size != 42 || pkg.SHA256 != "abc" {
		t.Fatalf("decoded wrong: %+v", pkg)
	}
}
