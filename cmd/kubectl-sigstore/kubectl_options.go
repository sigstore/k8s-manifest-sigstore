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

package main

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	cmdget "k8s.io/kubectl/pkg/cmd/get"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

const defaultChunkSize = 500

type KubectlOptions struct {
	cmdget.GetOptions
	ConfigFlags *genericclioptions.ConfigFlags
}

func (o *KubectlOptions) SetNamespaceOptions() error {
	var err error
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(o.ConfigFlags.WithDeprecatedPasswordFlag())
	f := cmdutil.NewFactory(matchVersionKubeConfigFlags)
	o.Namespace, o.ExplicitNamespace, err = f.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return errors.Wrap(err, "failed to set namespace options")
	}
	if o.AllNamespaces {
		o.ExplicitNamespace = false
	}
	return nil
}

func (o *KubectlOptions) Get(args []string, overrideNamespace string) ([]unstructured.Unstructured, error) {
	if o.ConfigFlags == nil {
		return nil, errors.New("kubectl client config is nil")
	}

	namespace := o.Namespace
	if overrideNamespace != "" {
		namespace = overrideNamespace
	}

	chunkSize := defaultChunkSize
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(o.ConfigFlags.WithDeprecatedPasswordFlag())
	f := cmdutil.NewFactory(matchVersionKubeConfigFlags)
	r := f.NewBuilder().
		Unstructured().
		NamespaceParam(namespace).DefaultNamespace().AllNamespaces(o.AllNamespaces).
		FilenameParam(o.ExplicitNamespace, &o.FilenameOptions).
		LabelSelectorParam(o.LabelSelector).
		FieldSelectorParam(o.FieldSelector).
		RequestChunksOf(int64(chunkSize)).
		ResourceTypeOrNameArgs(true, args...).
		ContinueOnError().
		Latest().
		Flatten().
		Do()
	if err := r.Err(); err != nil {
		return nil, errors.Wrap(err, "failed to call REST API for getting resources")
	}
	infos, err := r.Infos()
	if err != nil {
		return nil, errors.Wrap(err, "failed to get object infos after getting resources")
	}
	allErrs := []string{}
	objs := []unstructured.Unstructured{}
	for ix := range infos {
		obj := infos[ix].Object
		unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
		if err != nil {
			allErrs = append(allErrs, err.Error())
		}
		objs = append(objs, unstructured.Unstructured{Object: unstructuredObj})
	}
	if len(objs) == 0 && len(allErrs) > 0 {
		return nil, fmt.Errorf("error occurred during object conversion: %s", strings.Join(allErrs, "; "))
	}
	return objs, nil
}
