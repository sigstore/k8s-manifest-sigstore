//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package util

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
<<<<<<< HEAD
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
=======
	"sync"
>>>>>>> 5ea58a8 (update xonxurrency)
	"time"
)

var localCacheEnvKey = "K8S_MANIFEST_LOCAL_FILE_CACHE"

var globalCache Cache

var defaultLocalFileCacheTTL time.Duration = 180
var defaultOnMemoryCacheTTL time.Duration = 30

// ensure these implement Cache interface
var _ Cache = &OnMemoryCache{}
var _ Cache = &LocalFileCache{}

type CacheType string

const (
	CacheTypeUnknown CacheType = ""
	CacheTypeMemory  CacheType = "memory"
	CacheTypeFile    CacheType = "file"
)

type Cache interface {
	Set(key string, value ...interface{}) error
	Get(key string) ([]interface{}, error)
}

type cachedObject struct {
	timestamp time.Time
	object    []interface{}
}

type OnMemoryCache struct {
	TTL  time.Duration
	data map[string]cachedObject
	mu   sync.RWMutex
}

func (c *OnMemoryCache) Set(key string, value ...interface{}) error {
	if c.data == nil {
		c.data = map[string]cachedObject{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[key] = cachedObject{
		timestamp: time.Now().UTC(),
		object:    value,
	}
	return nil
}

func (c *OnMemoryCache) Get(key string) ([]interface{}, error) {
	if c.data == nil {
		c.data = map[string]cachedObject{}
	}
	c.clearExpiredData()

	c.mu.RLock()
	defer c.mu.RUnlock()
	obj, ok := c.data[key]
	if !ok {
		return nil, fmt.Errorf("no cached data is found with key `%s`", key)
	}
	return obj.object, nil
}

func (c *OnMemoryCache) clearExpiredData() {
	if c.data == nil {
		c.data = map[string]cachedObject{}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	newData := map[string]cachedObject{}
	for key, obj := range c.data {
		now := time.Now().UTC()
		if now.Sub(obj.timestamp) > c.TTL {
			continue
		}
		newData[key] = obj
	}
	c.data = newData
}

type LocalFileCache struct {
	TTL     time.Duration
	baseDir string

	mem *OnMemoryCache
}

func (c *LocalFileCache) Set(key string, value ...interface{}) error {
	if !c.baseDirExists() {
		c.initBaseDir()
	}
	if c.mem == nil {
		c.mem = c.initMem()
	}
	err := c.mem.Set(key, value...)
	if err != nil {
		return err
	}

	fpath := c.genFileNameFromKey(key)
	valueBytes, err := json.Marshal(value)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(fpath, valueBytes, 0644)
	if err != nil {
		return err
	}
	return nil
}

func (c *LocalFileCache) Get(key string) ([]interface{}, error) {
	if !c.baseDirExists() {
		c.initBaseDir()
	}
	if c.mem == nil {
		c.mem = c.initMem()
	}
	c.clearExpiredData()

	value1, err := c.mem.Get(key)
	if err == nil {
		return value1, nil
	}

	fpath := c.genFileNameFromKey(key)
	valueBytes, err := ioutil.ReadFile(fpath)
	if err != nil {
		return nil, err
	}
	var value2 []interface{}
	err = json.Unmarshal(valueBytes, &value2)
	if err != nil {
		return nil, err
	}
	return value2, nil
}

// generate a filename from a key
func (c *LocalFileCache) genFileNameFromKey(key string) string {
	keyHash := sha256.Sum256([]byte(key))
	fname := base64.StdEncoding.EncodeToString(keyHash[:])
	fname = strings.ReplaceAll(fname, "=", "")
	fname = strings.ReplaceAll(fname, "/", "")
	fname = strings.ReplaceAll(fname, "+", "")
	fpath := filepath.Join(c.baseDir, fname)
	return fpath
}

func (c *LocalFileCache) initBaseDir() error {
	if c.baseDir == "" {
		c.baseDir = GetCacheBaseDir()
	}
	return os.MkdirAll(c.baseDir, 0777)
}

func (c *LocalFileCache) baseDirExists() bool {
	if c.baseDir == "" {
		c.baseDir = GetCacheBaseDir()
	}
	_, err := os.Stat(c.baseDir)
	return err == nil
}
func (c *LocalFileCache) clearExpiredData() error {
	if c.mem == nil {
		c.mem = c.initMem()
	}
	c.mem.clearExpiredData()

	var err error
	var fds []os.FileInfo
	if fds, err = ioutil.ReadDir(c.baseDir); err != nil {
		return err
	}
	for _, fd := range fds {
		if fd.IsDir() {
			continue
		} else {
			fname := path.Join(c.baseDir, fd.Name())
			modTime := fd.ModTime().UTC()
			now := time.Now().UTC()
			if now.Sub(modTime) > c.TTL {
				err = os.Remove(fname)
				if err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (c *LocalFileCache) initMem() *OnMemoryCache {
	return &OnMemoryCache{TTL: c.TTL, data: map[string]cachedObject{}}
}

func GetCacheBaseDir() string {
	return filepath.Join(GetHomeDir(), ".sigstore", "k8smanifest", "cache")
}

func IsLocalCacheEnabeld() bool {
	enabled, _ := strconv.ParseBool(os.Getenv(localCacheEnvKey))
	return enabled
}

func initGlobalCache() {
	if IsLocalCacheEnabeld() {
		globalCache = &LocalFileCache{TTL: defaultLocalFileCacheTTL * time.Second}
	} else {
		globalCache = &OnMemoryCache{TTL: defaultOnMemoryCacheTTL * time.Second}
	}
}

func SetCache(key string, value ...interface{}) error {
	return globalCache.Set(key, value...)
}

func GetCache(key string) ([]interface{}, error) {
	return globalCache.Get(key)
}
