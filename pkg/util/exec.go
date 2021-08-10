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
	"bytes"
	"io"
	"os"
	"os/exec"
	"reflect"
	"time"

	"github.com/pkg/errors"
)

func CmdExec(baseCmd string, args ...string) (string, error) {
	cmd := exec.Command(baseCmd, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", errors.Wrap(err, stderr.String())
	}
	out := stdout.String()
	return out, nil
}

func SilentExecFunc(f interface{}, i ...interface{}) ([]interface{}, string) {
	// if f is not a function, exit this
	if reflect.ValueOf(f).Type().Kind() != reflect.Func {
		return nil, ""
	}

	// create virtual output
	rStdout, wStdout, _ := os.Pipe()
	rStderr, wStderr, _ := os.Pipe()
	channel := make(chan string)

	// backup all output
	backupStdout := os.Stdout
	backupStderr := os.Stderr

	// overwrite output configuration with virtual output
	os.Stdout = wStdout
	os.Stderr = wStderr

	// set a channel as a stdout buffer
	go func(out chan string, readerStdout *os.File, readerStderr *os.File) {
		var bufStdout bytes.Buffer
		_, _ = io.Copy(&bufStdout, readerStdout)
		if bufStdout.Len() > 0 {
			out <- bufStdout.String()
		}

		var bufStderr bytes.Buffer
		_, _ = io.Copy(&bufStderr, readerStderr)
		if bufStderr.Len() > 0 {
			out <- bufStderr.String()
		}
	}(channel, rStdout, rStderr)

	// configure channel so that all recevied string would be inserted into vStdout
	vStdout := ""
	go func() {
		for {
			out := <-channel
			vStdout += out
		}
	}()

	// call the function
	in := []reflect.Value{}
	for _, ii := range i {
		in = append(in, reflect.ValueOf(ii))
	}
	o := []interface{}{}
	out := reflect.ValueOf(f).Call(in)
	for _, oi := range out {
		o = append(o, oi.Interface())
	}

	// close vitual output
	_ = wStdout.Close()
	_ = wStderr.Close()
	time.Sleep(10 * time.Millisecond)

	// restore original output configuration
	os.Stdout = backupStdout
	os.Stderr = backupStderr
	return o, vStdout
}
