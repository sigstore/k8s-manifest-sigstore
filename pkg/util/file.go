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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	filetimes "github.com/djherbis/times"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

const EnvVarFileRefPrefix = "env://"

// AnnotationWriter represents the embedAnnotation function
type AnnotationWriter func([]byte, map[string]interface{}) ([]byte, error)

type MutateOptions struct {
	AW          AnnotationWriter
	Annotations map[string]interface{}
}

func TarGzCompress(src string, buf io.Writer, moList ...*MutateOptions) error {

	// tar > gzip > buf
	zr := gzip.NewWriter(buf)
	tw := tar.NewWriter(zr)

	var errV error

	// we cannot use os.MkdirTemp() here because it creates a direcotry with a different name everytime
	// it results in inconsistent compression result that means inconsistent message even for the identical input.
	// instead, we use a temporary directory which is named like `compression-tar-gz-<INPUT_FILE_DIGEST>`.
	digest, err := getSourceDigest(src, moList)
	if err != nil {
		return errors.Wrap(err, "error occurred during getting digest of the input for tar gz compression")
	}
	dir := filepath.Join(os.TempDir(), "compressing-tar-gz-"+digest[:12])
	err = os.MkdirAll(dir, 0755)
	if err != nil {
		return errors.Wrap(err, "error occurred during creating temp dir for tar gz compression")
	}
	defer os.RemoveAll(dir)
	log.Debugf("use temp dir %s for signing working directory", dir)

	// create tmpSrc dir and copy src files into this
	// in order to avoid relative path error on decompression like `tar xzf: Path contains '..'`
	basename := filepath.Base(src)
	// filepath.Base() returns ".." for an input like "../"
	// replace it with empty string to avoid the case of filepath.Join(tmpDir, "..") which could cause some permission errors
	if basename == ".." {
		basename = ""
	}
	tmpSrc := filepath.Join(dir, basename)
	err = copyDir(src, tmpSrc)
	if err != nil {
		return errors.Wrap(err, "error occurred during copying src dir for tar gz compression")
	}
	tarGzSrc := tmpSrc
	log.Debugf("finished to copy from %s to %s", src, tmpSrc)

	// if mutation option is specified, should mutate files before tar gz compression
	// in order to avoid file header inconsistency
	if len(moList) > 0 {
		errV = filepath.Walk(tmpSrc, func(file string, fi os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			// if not a dir, write file content
			if !fi.IsDir() {
				f, err := os.ReadFile(file)
				if err != nil {
					return err
				}
				// get original timestamps
				tStat, err := filetimes.Stat(file)
				if err != nil {
					return err
				}

				data := f
				for _, mo := range moList {
					if mo == nil {
						continue
					}
					data, err = mo.AW(data, mo.Annotations)
					if err != nil {
						return err
					}
				}
				log.Debugf("message YAML file mutated by MutationOption: %s\n%s", file, string(data))

				err = os.WriteFile(file, data, fi.Mode())
				if err != nil {
					return err
				}

				// set the original timestamp metadata to generate consistent compression results everytime
				err = os.Chtimes(file, tStat.AccessTime(), tStat.ModTime())
				if err != nil {
					return err
				}
			}
			return nil
		})

		if errV != nil {
			return errV
		}
	}

	// tar gz compression
	// walk through every file in the folder
	errV = filepath.Walk(tarGzSrc, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		// generate tar header
		header, err := tar.FileInfoHeader(fi, file)
		if err != nil {
			return err
		}

		// must provide real name
		// (see https://golang.org/src/archive/tar/common.go?#L626)
		header.Name = filepath.ToSlash(file)

		// write header
		if err := tw.WriteHeader(header); err != nil {
			return err
		}
		// if not a dir, write file content
		if !fi.IsDir() {
			data, err := os.ReadFile(file)
			if err != nil {
				return err
			}

			if _, err := io.Copy(tw, bytes.NewReader(data)); err != nil {
				return err
			}
		}
		return nil
	})

	if errV != nil {
		return errV
	}

	// produce tar
	if errV = tw.Close(); errV != nil {
		return errV
	}
	// produce gzip
	if errV = zr.Close(); errV != nil {
		return errV
	}
	return nil
}

func TarGzDecompress(src io.Reader, dst string) error {
	// ungzip
	zr, err := gzip.NewReader(src)
	if err != nil {
		return err
	}
	// untar
	tr := tar.NewReader(zr)

	// uncompress each element
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}
		if err != nil {
			return err
		}
		if strings.Contains(header.Name, "..") {
			return fmt.Errorf("a file contains \"..\" in its path cannot be decompressed, but `%s` has been found", header.Name)
		}

		// add dst + re-format slashes according to system
		target := filepath.Join(dst, header.Name)
		// if no join is needed, replace with ToSlash:
		// target = filepath.ToSlash(header.Name)

		// check the type
		switch header.Typeflag {

		// if its a dir and it doesn't exist create it (with 0755 permission)
		case tar.TypeDir:
			if _, err := os.Stat(target); err != nil {
				if err := os.MkdirAll(target, 0755); err != nil {
					return err
				}
			}
		// if it's a file create it (with same permission)
		case tar.TypeReg:
			targetDir := filepath.Dir(target)
			err := os.MkdirAll(targetDir, 0755)
			if err != nil {
				return errors.Wrap(err, "os.MkdirAll() failed while decompressing tar gz")
			}
			fileToWrite, err := os.OpenFile(target, os.O_CREATE|os.O_RDWR, os.FileMode(header.Mode))
			if err != nil {
				return err
			}
			// copy over contents
			if _, err := io.Copy(fileToWrite, tr); err != nil {
				return err
			}
			// manually close here after each file operation; defering would cause each file close
			// to wait until all operations have completed.
			fileToWrite.Close()
		}
	}
	return nil
}

// copy an entire directory recursively
func copyDir(src string, dst string) error {
	var err error
	var fds []fs.DirEntry
	var srcinfo os.FileInfo

	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}

	if srcinfo.IsDir() {
		if err = os.MkdirAll(dst, srcinfo.Mode()); err != nil {
			return err
		}

		if fds, err = os.ReadDir(src); err != nil {
			return err
		}
		for _, fd := range fds {
			srcfp := path.Join(src, fd.Name())
			dstfp := path.Join(dst, fd.Name())

			if fd.IsDir() {
				if err = copyDir(srcfp, dstfp); err != nil {
					return err
				}
			} else {
				if err = copyFile(srcfp, dstfp); err != nil {
					return err
				}
			}
		}
	} else {
		if err = copyFile(src, dst); err != nil {
			return err
		}
	}

	return nil
}

// copy a single file
func copyFile(src string, dst string) error {
	fi, err := os.Stat(src)
	if err != nil {
		return err
	}

	input, err := os.ReadFile(src)
	if err != nil {
		return err
	}

	err = os.WriteFile(dst, input, fi.Mode())
	if err != nil {
		return err
	}

	// set the original timestamp metadata to generate consistent compression results everytime
	tStat, err := filetimes.Stat(src)
	if err != nil {
		return err
	}
	err = os.Chtimes(dst, tStat.AccessTime(), tStat.ModTime())
	if err != nil {
		return err
	}

	return nil
}

func IsDir(path string) (bool, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return fi.IsDir(), nil
}

func GetHomeDir() string {
	dir, err := os.UserHomeDir()
	if err != nil {
		dir = "/root"
	}
	return dir
}

func LoadFileDataInEnvVar(envVarRef string) ([]byte, error) {
	envVarName := strings.TrimPrefix(envVarRef, EnvVarFileRefPrefix)
	dataStr, found := os.LookupEnv(envVarName)
	if !found {
		return nil, fmt.Errorf("`$%s` is not found in environment variables", envVarName)
	}
	return []byte(dataStr), nil
}

func getSourceDigest(srcPath string, moList []*MutateOptions) (string, error) {
	yamls, err := FindYAMLsInDir(srcPath)
	if err != nil {
		return "", err
	}
	mYamls := [][]byte{}
	for _, yaml := range yamls {
		for _, mo := range moList {
			if mo == nil {
				continue
			}
			mYaml, err := mo.AW(yaml, mo.Annotations)
			if err != nil {
				return "", err
			}
			mYamls = append(mYamls, mYaml)
		}
	}
	oneYaml := ConcatenateYAMLs(mYamls)
	digest := sha256.Sum256(oneYaml)
	return fmt.Sprintf("%x", digest), nil
}
