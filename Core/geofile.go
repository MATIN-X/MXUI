// MX-UI VPN Panel
// Core/geofile.go
// GeoIP/GeoSite Management

package core

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	DefaultGeoPath     = "/opt/mxui/data/geo"
	DefaultGeoIPFile   = "geoip.dat"
	DefaultGeoSiteFile = "geosite.dat"
	GeoIPDownloadURL   = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
	GeoSiteDownloadURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
)

type GeoFileManager struct {
	basePath    string
	geoIPPath   string
	geoSitePath string
	lastUpdate  time.Time
	mu          sync.RWMutex
}

type GeoFileInfo struct {
	Type      string    `json:"type"`
	Path      string    `json:"path"`
	Size      int64     `json:"size"`
	Hash      string    `json:"hash"`
	ModTime   time.Time `json:"mod_time"`
	Available bool      `json:"available"`
}

var GeoFiles *GeoFileManager

func InitGeoFileManager(basePath string) error {
	if basePath == "" {
		basePath = DefaultGeoPath
	}
	GeoFiles = &GeoFileManager{
		basePath:    basePath,
		geoIPPath:   filepath.Join(basePath, DefaultGeoIPFile),
		geoSitePath: filepath.Join(basePath, DefaultGeoSiteFile),
	}
	if err := os.MkdirAll(basePath, 0755); err != nil {
		return err
	}
	if !GeoFiles.FilesExist() {
		go GeoFiles.UpdateAll()
	}
	return nil
}

func (gm *GeoFileManager) FilesExist() bool {
	_, err1 := os.Stat(gm.geoIPPath)
	_, err2 := os.Stat(gm.geoSitePath)
	return err1 == nil && err2 == nil
}

func (gm *GeoFileManager) GetGeoIPPath() string   { return gm.geoIPPath }
func (gm *GeoFileManager) GetGeoSitePath() string { return gm.geoSitePath }

func (gm *GeoFileManager) GetInfo() map[string]*GeoFileInfo {
	return map[string]*GeoFileInfo{
		"geoip":   gm.getFileInfo(gm.geoIPPath, "geoip"),
		"geosite": gm.getFileInfo(gm.geoSitePath, "geosite"),
	}
}

func (gm *GeoFileManager) getFileInfo(path, geoType string) *GeoFileInfo {
	info := &GeoFileInfo{Type: geoType, Path: path}
	stat, err := os.Stat(path)
	if err != nil {
		return info
	}
	info.Available = true
	info.Size = stat.Size()
	info.ModTime = stat.ModTime()
	if hash, err := gm.calculateHash(path); err == nil {
		info.Hash = hash
	}
	return info
}

func (gm *GeoFileManager) calculateHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	io.Copy(h, f)
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (gm *GeoFileManager) UpdateAll() error {
	var errs []string
	if err := gm.downloadFile(GeoIPDownloadURL, gm.geoIPPath); err != nil {
		errs = append(errs, err.Error())
	}
	if err := gm.downloadFile(GeoSiteDownloadURL, gm.geoSitePath); err != nil {
		errs = append(errs, err.Error())
	}
	gm.lastUpdate = time.Now()
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func (gm *GeoFileManager) downloadFile(url, dest string) error {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	tmpFile := dest + ".tmp"
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http status: %s", resp.Status)
	}

	out, err := os.Create(tmpFile)
	if err != nil {
		return err
	}

	var reader io.Reader = resp.Body
	if strings.HasSuffix(url, ".gz") {
		gzReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			out.Close()
			os.Remove(tmpFile)
			return err
		}
		defer gzReader.Close()
		reader = gzReader
	}

	_, err = io.Copy(out, reader)
	out.Close()
	if err != nil {
		os.Remove(tmpFile)
		return err
	}

	return os.Rename(tmpFile, dest)
}
