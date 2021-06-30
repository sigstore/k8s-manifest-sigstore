//
// Copyright 2020 IBM Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package util

import (
	"fmt"
	"time"
)

var _ Cache = &OnMemoryCache{}

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
}

func (c *OnMemoryCache) Set(key string, value ...interface{}) error {
	if c.data == nil {
		c.data = map[string]cachedObject{}
	}

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
