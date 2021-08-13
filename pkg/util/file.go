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
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
)

// AnnotationWriter represents the embedAnnotation function
type AnnotationWriter func([]byte, map[string]interface{}) ([]byte, error)

type MutateOptions struct {
	AW          AnnotationWriter
	Annotations map[string]interface{}
}

func TarGzCompress(src string, buf io.Writer, mo *MutateOptions) error {

	// tar > gzip > buf
	zr := gzip.NewWriter(buf)
	tw := tar.NewWriter(zr)

	var errV error

	dir, err := ioutil.TempDir("", "compressing-tar-gz")
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
	if mo != nil {
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

				data, err := mo.AW(f, mo.Annotations)
				if err != nil {
					return err
				}

				err = os.WriteFile(file, data, fi.Mode())
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

// check for path traversal and correct forward slashes
func validRelPath(p string) bool {
	if p == "" || strings.Contains(p, `\`) || strings.HasPrefix(p, "/") || strings.Contains(p, "../") {
		return false
	}
	return true
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

		// validate name against path traversal
		if !validRelPath(header.Name) {
			return fmt.Errorf("tar contained invalid name error %q\n", header.Name)
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
	var fds []os.FileInfo
	var srcinfo os.FileInfo

	if srcinfo, err = os.Stat(src); err != nil {
		return err
	}

	if srcinfo.IsDir() {
		if err = os.MkdirAll(dst, srcinfo.Mode()); err != nil {
			return err
		}

		if fds, err = ioutil.ReadDir(src); err != nil {
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

	input, err := ioutil.ReadFile(src)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(dst, input, fi.Mode())
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
