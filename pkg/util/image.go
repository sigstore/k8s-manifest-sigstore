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

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
)

func PullImage(imageRef string) (v1.Image, error) {
	ref, err := name.ParseReference(imageRef)
	if err != nil {
		return nil, err
	}
	img, err := remote.Image(ref, remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, err
	}
	return img, nil
}

func GetBlob(layer v1.Layer) ([]byte, error) {
	rc, err := layer.Compressed()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get blob in image")
	}
	defer rc.Close()
	return ioutil.ReadAll(rc)
}

func GenerateConcatYAMLsFromImage(img v1.Image) ([]byte, error) {
	layers, err := img.Layers()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get layers in image")
	}
	if len(layers) == 0 {
		return nil, errors.New("failed to get blob in image; this image has no layers")
	}
	yamls := [][]byte{}
	sumErr := []string{}
	for _, layer := range layers {
		blob, err := GetBlob(layer)
		if err != nil {
			sumErr = append(sumErr, errors.Wrap(err, "failed to get artifact from image layer").Error())
			continue
		}
		blobStream := bytes.NewBuffer(blob)
		yamlsInLayer, err := getYAMLsInArtifact(blobStream)
		if err != nil {
			sumErr = append(sumErr, errors.Wrap(err, "failed to decompress tar gz blob").Error())
			continue
		}
		yamls = append(yamls, yamlsInLayer...)
	}
	if len(yamls) == 0 && len(sumErr) > 0 {
		return nil, errors.New(strings.Join(sumErr, "; "))
	}
	concatYamls := ConcatenateYAMLs(yamls)
	return concatYamls, nil
}

func getYAMLsInArtifact(gzipStream io.Reader) ([][]byte, error) {
	uncompressedStream, err := gzip.NewReader(gzipStream)
	if err != nil {
		return nil, errors.Wrap(err, "gzip.NewReader() failed while decompressing tar gz")
	}

	tarReader := tar.NewReader(uncompressedStream)

	dir, err := ioutil.TempDir("", "decompressed-tar-gz")
	if err != nil {
		return nil, errors.Wrap(err, "gzip.NewReader() failed while decompressing tar gz")
	}
	defer os.RemoveAll(dir)

	for true {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, errors.Wrap(err, "tarReader.Next() failed while decompressing tar gz")
		}

		switch header.Typeflag {
		case tar.TypeDir:
			fpath := filepath.Join(dir, header.Name)
			if err := os.Mkdir(fpath, 0755); err != nil {
				return nil, errors.Wrap(err, "os.Mkdir() failed while decompressing tar gz")
			}
		case tar.TypeReg:
			fpath := filepath.Join(dir, header.Name)
			fdir := filepath.Dir(fpath)
			err := os.MkdirAll(fdir, 0755)
			if err != nil {
				return nil, errors.Wrap(err, "os.MkdirAll() failed while decompressing tar gz")
			}
			outFile, err := os.Create(fpath)
			if err != nil {
				return nil, errors.Wrap(err, "os.Create() failed while decompressing tar gz")
			}
			defer outFile.Close()
			if _, err := io.Copy(outFile, tarReader); err != nil {
				return nil, errors.Wrap(err, "io.Copy() failed while decompressing tar gz")
			}
		default:
			return nil, fmt.Errorf("faced uknown type %s in %s while decompressing tar gz", string(header.Typeflag), header.Name)
		}
	}

	foundYAMLs := [][]byte{}
	err = filepath.Walk(dir, func(fpath string, info os.FileInfo, err error) error {
		if err == nil && (path.Ext(info.Name()) == ".yaml" || path.Ext(info.Name()) == ".yml") {
			yamlBytes, err := ioutil.ReadFile(fpath)
			if err == nil && isK8sResourceYAML(yamlBytes) {
				foundYAMLs = append(foundYAMLs, yamlBytes)
			}
		}
		return nil
	})
	return foundYAMLs, nil
}
