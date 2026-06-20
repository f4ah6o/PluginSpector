// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package scanner

import "testing"

func TestIsGitURLRejectsHostSubstringSpoofing(t *testing.T) {
	bad := []string{
		"https://github.com.evil.tld/org/repo",
		"https://notgithub.com/org/repo",
		"https://gitlab.com.attacker.example/x/y",
		"https://bitbucket.org.evil.tld/x/y",
	}
	for _, u := range bad {
		if isGitURL(u) {
			t.Fatalf("%s must not be detected as a known git host", u)
		}
	}

	good := []string{
		"https://github.com/org/repo",
		"https://gitlab.com/org/repo",
		"https://bitbucket.org/org/repo",
		"git@github.com:org/repo.git",
	}
	for _, u := range good {
		if !isGitURL(u) {
			t.Fatalf("%s should be detected as a git URL", u)
		}
	}
}

func TestIsKnownGitHost(t *testing.T) {
	good := []string{"github.com", "gitlab.com", "bitbucket.org", "GITHUB.COM", "GitHub.Com", "github.com."}
	for _, h := range good {
		if !isKnownGitHost(h) {
			t.Fatalf("%q should be a known git host", h)
		}
	}

	bad := []string{
		"github.com.evil.tld",
		"notgithub.com",
		"gitlab.com.attacker.example",
		"bitbucket.org.evil.tld",
		"evil-github.com",
		"",
	}
	for _, h := range bad {
		if isKnownGitHost(h) {
			t.Fatalf("%q must not be a known git host", h)
		}
	}
}

func TestIsGitURLPreservesExistingBehavior(t *testing.T) {
	// Archive URLs on known hosts must route to the downloader, not git clone.
	archiveURLs := []string{
		"https://github.com/org/repo/archive/refs/heads/main.zip",
		"https://gitlab.com/org/repo/-/archive/main.zip",
	}
	for _, u := range archiveURLs {
		if isGitURL(u) {
			t.Fatalf("archive URL %s must not be treated as a git URL", u)
		}
	}

	// Raw/blob file URLs must not be cloned.
	fileURLs := []string{
		"https://github.com/org/repo/raw/main/SKILL.md",
		"https://github.com/org/repo/blob/main/script.sh",
		"https://github.com/org/repo/blob/main/tool.py",
	}
	for _, u := range fileURLs {
		if isGitURL(u) {
			t.Fatalf("file URL %s must not be treated as a git URL", u)
		}
	}

	// Generic .git URLs on unknown hosts are still accepted (HTTPS and SCP).
	if !isGitURL("https://codeberg.org/org/repo.git") {
		t.Fatal("https://codeberg.org/org/repo.git should be treated as a git URL")
	}
	if !isGitURL("git@codeberg.org:org/repo.git") {
		t.Fatal("git@codeberg.org:org/repo.git should be treated as a git URL")
	}
	if !isGitURL("git@git.company.example:team/repo.git") {
		t.Fatal("git@git.company.example:team/repo.git should be treated as a git URL")
	}
	// SCP URLs with no .git suffix and an unknown host should not be accepted.
	if isGitURL("git@evil.example.com:malicious/thing") {
		t.Fatal("git@evil.example.com:malicious/thing must not be treated as a git URL")
	}
}
