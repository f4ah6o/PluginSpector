// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Input handler: normalizes git URLs, file URLs, zip files, single markdown
// files, and local directories into a scannable directory. Ported from
// src/pluginspector/input_handler.py.

package scanner

import (
	"archive/zip"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

const (
	maxDownloadBytes          = 50 * 1024 * 1024
	maxArchiveEntries         = 1_000
	maxArchiveExpandedBytes   = 200 * 1024 * 1024
	maxArchiveRatio           = 100
	maxArchiveCompressedBytes = 50 * 1024 * 1024
)

// inputHandler resolves an input path to a scannable directory, tracking any
// temp directory it creates so the caller can clean it up.
type inputHandler struct {
	tempDir string
}

func (h *inputHandler) tempDirPath() (string, error) {
	if h.tempDir == "" {
		d, err := os.MkdirTemp("", "pluginspector_")
		if err != nil {
			return "", err
		}
		h.tempDir = d
	}
	return h.tempDir, nil
}

func (h *inputHandler) cleanup() {
	if h.tempDir != "" {
		_ = os.RemoveAll(h.tempDir)
		h.tempDir = ""
	}
}

// resolve returns (dir, sourceType, error). sourceType is one of
// git|url|zip|file|directory.
func (h *inputHandler) resolve(inputPath string) (string, string, error) {
	inputPath = strings.TrimSpace(inputPath)
	switch {
	case isGitURL(inputPath):
		d, err := h.cloneGit(inputPath)
		return d, "git", err
	case isFileURL(inputPath):
		d, err := h.downloadFile(inputPath)
		return d, "url", err
	case strings.HasSuffix(inputPath, ".zip"):
		d, err := h.extractZip(inputPath)
		return d, "zip", err
	case strings.HasSuffix(inputPath, ".md"):
		d, err := h.wrapSingleFile(inputPath)
		return d, "file", err
	}
	info, err := os.Stat(inputPath)
	if err == nil && info.IsDir() {
		abs, _ := filepath.Abs(inputPath)
		return abs, "directory", nil
	}
	if err == nil && !info.IsDir() {
		d, werr := h.wrapSingleFile(inputPath)
		return d, "file", werr
	}
	return "", "", fmt.Errorf("cannot determine input type for: %s\nSupported formats: Git URL, file URL, .zip file, .md file, or directory", inputPath)
}

// isKnownGitHost reports whether host is exactly one of the known Git hosting
// services. Lowercasing and trailing-dot removal guard against trivial variants.
// Substring matching is intentionally avoided: "github.com.evil.tld" must not
// match "github.com".
func isKnownGitHost(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	switch host {
	case "github.com", "gitlab.com", "bitbucket.org":
		return true
	default:
		return false
	}
}

func isGitURL(path string) bool {
	// SCP-style URLs (git@host:org/repo.git) — parse the host and validate it
	// with exact matching so "git@github.com.evil.tld:x/y.git" is rejected.
	if strings.HasPrefix(path, "git@") {
		withoutPrefix := strings.TrimPrefix(path, "git@")
		colonIdx := strings.Index(withoutPrefix, ":")
		if colonIdx < 0 {
			return false
		}
		return isKnownGitHost(withoutPrefix[:colonIdx])
	}
	if !(strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://")) {
		return false
	}
	// Downloadable archive URLs (e.g. github.com/org/repo/archive/refs/heads/
	// main.zip) must go to the downloader/extractor, not `git clone`.
	if strings.HasSuffix(path, ".zip") {
		return false
	}
	parsed, err := url.Parse(path)
	if err != nil {
		return false
	}
	if isKnownGitHost(parsed.Hostname()) {
		if strings.Contains(path, "/raw/") || strings.Contains(path, "/blob/") ||
			strings.HasSuffix(path, ".md") || strings.HasSuffix(path, ".py") || strings.HasSuffix(path, ".sh") {
			return false
		}
		return true
	}
	return strings.HasSuffix(path, ".git")
}

func isFileURL(path string) bool {
	if !(strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://")) {
		return false
	}
	return !isGitURL(path)
}

func (h *inputHandler) cloneGit(gitURL string) (string, error) {
	tempDir, err := h.tempDirPath()
	if err != nil {
		return "", err
	}
	cloneDir := filepath.Join(tempDir, "repo")
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", gitURL, cloneDir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("git clone timed out after 60 seconds")
		}
		if _, lookErr := exec.LookPath("git"); lookErr != nil {
			return "", fmt.Errorf("git is not installed; please install git to scan repositories")
		}
		return "", fmt.Errorf("failed to clone repository: %s", strings.TrimSpace(string(out)))
	}
	return cloneDir, nil
}

func (h *inputHandler) downloadFile(fileURL string) (string, error) {
	tempDir, err := h.tempDirPath()
	if err != nil {
		return "", err
	}
	parsed, _ := url.Parse(fileURL)
	filename := filepath.Base(parsed.Path)
	if filename == "" || filename == "." || filename == "/" {
		filename = "SKILL.md"
	}
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(fileURL)
	if err != nil {
		return "", fmt.Errorf("failed to download file: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("failed to download file: HTTP %d", resp.StatusCode)
	}
	limited := io.LimitReader(resp.Body, maxDownloadBytes+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return "", fmt.Errorf("failed to download file: %w", err)
	}
	if len(content) > maxDownloadBytes {
		return "", fmt.Errorf("download exceeded %d MB limit: %s", maxDownloadBytes/(1024*1024), fileURL)
	}
	contentType := resp.Header.Get("Content-Type")
	if strings.HasSuffix(filename, ".zip") || strings.HasPrefix(contentType, "application/zip") {
		zipPath := filepath.Join(tempDir, "download.zip")
		if err := os.WriteFile(zipPath, content, 0o600); err != nil {
			return "", err
		}
		return h.extractZip(zipPath)
	}
	if err := os.WriteFile(filepath.Join(tempDir, filename), content, 0o600); err != nil {
		return "", err
	}
	return tempDir, nil
}

func (h *inputHandler) extractZip(zipPath string) (string, error) {
	info, err := os.Stat(zipPath)
	if err != nil {
		return "", fmt.Errorf("zip file not found: %s", zipPath)
	}
	compressedSize := info.Size()
	if compressedSize > maxArchiveCompressedBytes {
		return "", fmt.Errorf("archive too large (%d MB, limit %d MB): %s",
			compressedSize/(1024*1024), maxArchiveCompressedBytes/(1024*1024), zipPath)
	}
	tempDir, err := h.tempDirPath()
	if err != nil {
		return "", err
	}
	extractDir := filepath.Join(tempDir, "extracted")
	if err := os.MkdirAll(extractDir, 0o755); err != nil {
		return "", err
	}
	extractResolved, _ := filepath.Abs(extractDir)

	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		return "", fmt.Errorf("invalid zip file: %s", zipPath)
	}
	defer zr.Close()

	if len(zr.File) > maxArchiveEntries {
		return "", fmt.Errorf("archive has too many entries (%d, limit %d): %s", len(zr.File), maxArchiveEntries, zipPath)
	}
	var totalExpanded uint64
	for _, m := range zr.File {
		totalExpanded += m.UncompressedSize64
	}
	if totalExpanded > maxArchiveExpandedBytes {
		return "", fmt.Errorf("archive expands to too many bytes (%d MB, limit %d MB): %s",
			totalExpanded/(1024*1024), maxArchiveExpandedBytes/(1024*1024), zipPath)
	}
	if compressedSize > 0 && int64(totalExpanded)/compressedSize > maxArchiveRatio {
		return "", fmt.Errorf("archive expansion ratio too high (limit %dx) — possible zip bomb: %s", maxArchiveRatio, zipPath)
	}

	for _, m := range zr.File {
		if m.Mode()&os.ModeSymlink != 0 {
			continue
		}
		name := m.Name
		if filepath.IsAbs(name) || strings.HasPrefix(name, "/") {
			return "", fmt.Errorf("archive contains absolute path entry: %s", name)
		}
		clean := filepath.Clean(name)
		if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("archive contains path traversal entry: %s", name)
		}
		dest := filepath.Join(extractDir, clean)
		destResolved, _ := filepath.Abs(dest)
		rel, relErr := filepath.Rel(extractResolved, destResolved)
		if relErr != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("archive entry would escape extraction directory: %s", name)
		}
		if strings.HasSuffix(name, "/") {
			_ = os.MkdirAll(dest, 0o755)
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
			return "", err
		}
		if err := extractZipFile(m, dest); err != nil {
			return "", err
		}
	}

	entries, _ := os.ReadDir(extractDir)
	if len(entries) == 1 && entries[0].IsDir() {
		return filepath.Join(extractDir, entries[0].Name()), nil
	}
	return extractDir, nil
}

func extractZipFile(m *zip.File, dest string) error {
	rc, err := m.Open()
	if err != nil {
		return err
	}
	defer rc.Close()
	df, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer df.Close()
	_, err = io.Copy(df, io.LimitReader(rc, maxArchiveExpandedBytes))
	return err
}

func (h *inputHandler) wrapSingleFile(filePath string) (string, error) {
	if _, err := os.Stat(filePath); err != nil {
		return "", fmt.Errorf("file not found: %s", filePath)
	}
	tempDir, err := h.tempDirPath()
	if err != nil {
		return "", err
	}
	dest := filepath.Join(tempDir, filepath.Base(filePath))
	b, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(dest, b, 0o600); err != nil {
		return "", err
	}
	return tempDir, nil
}
