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
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/pkg/errors"
	cliopt "github.com/sigstore/cosign/v2/cmd/cosign/cli/options"
	"github.com/spf13/afero"
)

func PullImage(resBundleRef string, allowInsecure bool) (v1.Image, error) {
	ref, err := name.ParseReference(resBundleRef)
	if err != nil {
		return nil, err
	}
	regOpt := cliopt.RegistryOptions{}
	if allowInsecure {
		regOpt.AllowInsecure = true
	}
	reqCliOpt := regOpt.GetRegistryClientOpts(context.Background())
	img, err := remote.Image(ref, reqCliOpt...)
	if err != nil {
		return nil, err
	}
	return img, nil
}

func GetImageDigest(resBundleRef string, allowInsecure bool) (string, error) {
	ref, err := name.ParseReference(resBundleRef)
	if err != nil {
		return "", err
	}
	regOpt := cliopt.RegistryOptions{}
	if allowInsecure {
		regOpt.AllowInsecure = true
	}
	reqCliOpt := regOpt.GetRegistryClientOpts(context.Background())
	img, err := remote.Image(ref, reqCliOpt...)
	if err != nil {
		return "", err
	}
	hash, err := img.Digest()
	if err != nil {
		return "", err
	}
	return hash.String(), nil
}

func GetBlob(layer v1.Layer) ([]byte, error) {
	rc, err := layer.Compressed()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get blob in image")
	}
	defer rc.Close()
	return io.ReadAll(rc)
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
		yamlsInLayer, err := GetYAMLsInArtifact(blob)
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

func GetYAMLsInArtifact(blob []byte) ([][]byte, error) {
	// first try reading the stream as raw YAML manifest
	yamls := SplitConcatYAMLs(blob)
	if len(yamls) > 0 {
		return yamls, nil
	}
	// then try decompressing tar gz file and load yamls inside the decompressed dir
	byteStream := bytes.NewBuffer(blob)
	uncompressedStream, err := gzip.NewReader(byteStream)
	if err != nil {
		return nil, errors.Wrap(err, "gzip.NewReader() failed while decompressing tar gz")
	}

	tarReader := tar.NewReader(uncompressedStream)

	memfs := afero.Afero{Fs: afero.NewMemMapFs()}
	dir, err := memfs.TempDir("", "decompressed-tar-gz")
	if err != nil {
		return nil, errors.Wrap(err, "gzip.NewReader() failed while decompressing tar gz")
	}
	defer func() {
		_ = memfs.RemoveAll(dir)
	}()

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return nil, errors.Wrap(err, "tarReader.Next() failed while decompressing tar gz")
		}

		// Skip files that have path starting with ".."
		// Ref: CWE-22
		if !strings.Contains(header.Name, "..") {
			continue
		}

		switch header.Typeflag {
		case tar.TypeDir:
			fpath := filepath.Join(dir, header.Name)
			if err := memfs.MkdirAll(fpath, 0755); err != nil {
				return nil, errors.Wrap(err, "memfs.MkdirAll() failed while decompressing tar gz")
			}
		case tar.TypeReg:
			fpath := filepath.Join(dir, header.Name)
			fdir := filepath.Dir(fpath)
			err := memfs.MkdirAll(fdir, 0755)
			if err != nil {
				return nil, errors.Wrap(err, "memfs.MkdirAll() failed while decompressing tar gz")
			}
			outFile, err := memfs.Create(fpath)
			if err != nil {
				return nil, errors.Wrap(err, "memfs.Create() failed while decompressing tar gz")
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
	err = memfs.Walk(dir, func(fpath string, info os.FileInfo, err error) error {
		if err == nil && (path.Ext(info.Name()) == ".yaml" || path.Ext(info.Name()) == ".yml") {
			yamlBytes, err := memfs.ReadFile(fpath)
			if err == nil && isK8sResourceYAML(yamlBytes) {
				foundYAMLs = append(foundYAMLs, yamlBytes)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return foundYAMLs, nil
}
