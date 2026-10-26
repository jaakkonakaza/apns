package main

import "testing"

func TestReleaseNotes(t *testing.T) {
	changelog := "# Changelog\n\n## Unreleased\n\nFuture work.\n\n## v1.0.0-beta.1\n\nFirst beta.\n\n### Included\n\n- A feature.\n\n## Release policy\n\nPolicy text.\n"
	got, err := releaseNotes("v1.0.0-beta.1", changelog)
	if err != nil {
		t.Fatal(err)
	}
	if want := "First beta.\n\n### Included\n\n- A feature.\n"; got != want {
		t.Fatalf("notes = %q, want %q", got, want)
	}
}

func TestReleaseNotesRejectInvalidReleases(t *testing.T) {
	for _, tc := range []struct{ name, tag, changelog string }{
		{"branch", "main", "## main\nNotes"},
		{"unsupported major", "v2.0.0", "## v2.0.0\nNotes"},
		{"leading zero", "v1.00.0", "## v1.00.0\nNotes"},
		{"missing entry", "v1.0.0", "## Unreleased\nNotes"},
		{"empty entry", "v1.0.0", "## v1.0.0\n\n## Release policy\nPolicy"},
		{"duplicate entry", "v1.0.0", "## v1.0.0\nNotes\n## v1.0.0\nOther notes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := releaseNotes(tc.tag, tc.changelog); err == nil {
				t.Fatal("invalid release accepted")
			}
		})
	}
}

func TestReleaseNotesAcceptVersionForms(t *testing.T) {
	for _, tag := range []string{"v1.0.0", "v1.2.3", "v1.0.0-alpha.1", "v1.0.0-beta.10", "v1.0.0-rc.1"} {
		if _, err := releaseNotes(tag, "## "+tag+"\nNotes"); err != nil {
			t.Errorf("%s: %v", tag, err)
		}
	}
}
