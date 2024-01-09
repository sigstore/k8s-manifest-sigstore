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

package cli

import (
	"fmt"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/cli-runtime/pkg/printers"
	"k8s.io/cli-runtime/pkg/resource"
	cmdapply "k8s.io/kubectl/pkg/cmd/apply"
	"k8s.io/kubectl/pkg/cmd/delete"
	cmdget "k8s.io/kubectl/pkg/cmd/get"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

const defaultChunkSize = 500

type KubectlOptions struct {
	ConfigFlags *genericclioptions.ConfigFlags
	PrintFlags  *genericclioptions.PrintFlags

	GetOptions   *cmdget.GetOptions
	ApplyOptions *cmdapply.ApplyOptions

	fieldManagerForApply string
}

func (o *KubectlOptions) SetKubeConfig(fpath, namespace string) {
	o.ConfigFlags.KubeConfig = &fpath
	if namespace != "" {
		o.ConfigFlags.Namespace = &namespace
	}
}

func (o *KubectlOptions) InitGet(cmd *cobra.Command) error {
	ioStreams := genericclioptions.IOStreams{In: cmd.InOrStdin(), Out: cmd.OutOrStdout(), ErrOut: cmd.ErrOrStderr()}
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(o.ConfigFlags.WithDeprecatedPasswordFlag())
	f := cmdutil.NewFactory(matchVersionKubeConfigFlags)
	o.GetOptions = cmdget.NewGetOptions("kubectl-sigstore", ioStreams)
	var err error
	o.GetOptions.Namespace, o.GetOptions.ExplicitNamespace, err = f.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return errors.Wrap(err, "failed to set namespace options")
	}
	if o.GetOptions.AllNamespaces {
		o.GetOptions.ExplicitNamespace = false
	}
	return nil
}

func (o *KubectlOptions) Get(args []string, overrideNamespace string) ([]unstructured.Unstructured, error) {
	if o.ConfigFlags == nil {
		return nil, errors.New("kubectl client config is nil")
	}

	namespace := o.GetOptions.Namespace
	if overrideNamespace != "" {
		namespace = overrideNamespace
	}

	chunkSize := defaultChunkSize
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(o.ConfigFlags.WithDeprecatedPasswordFlag())
	f := cmdutil.NewFactory(matchVersionKubeConfigFlags)
	r := f.NewBuilder().
		Unstructured().
		NamespaceParam(namespace).DefaultNamespace().AllNamespaces(o.GetOptions.AllNamespaces).
		FilenameParam(o.GetOptions.ExplicitNamespace, &o.GetOptions.FilenameOptions).
		LabelSelectorParam(o.GetOptions.LabelSelector).
		FieldSelectorParam(o.GetOptions.FieldSelector).
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

func (o *KubectlOptions) InitApply(cmd *cobra.Command, filename string) error {
	ioStreams := genericclioptions.IOStreams{In: cmd.InOrStdin(), Out: cmd.OutOrStdout(), ErrOut: cmd.ErrOrStderr()}
	matchVersionKubeConfigFlags := cmdutil.NewMatchVersionFlags(o.ConfigFlags.WithDeprecatedPasswordFlag())
	f := cmdutil.NewFactory(matchVersionKubeConfigFlags)

	options, err := cmdapply.NewApplyFlags(ioStreams).ToOptions(f, cmd, "kubectl sigstore", []string{})
	if err != nil {
		return err
	}
	o.ApplyOptions = options

	o.ApplyOptions.ServerSideApply = cmdutil.GetServerSideApplyFlag(cmd)
	o.ApplyOptions.ForceConflicts = cmdutil.GetForceConflictsFlag(cmd)
	o.ApplyOptions.DryRunStrategy, err = cmdutil.GetDryRunStrategy(cmd)
	if err != nil {
		return err
	}
	o.ApplyOptions.DynamicClient, err = f.DynamicClient()
	if err != nil {
		return err
	}
	o.ApplyOptions.FieldManager = cmdapply.GetApplyFieldManagerFlag(cmd, o.ApplyOptions.ServerSideApply)

	if o.ApplyOptions.ForceConflicts && !o.ApplyOptions.ServerSideApply {
		return fmt.Errorf("--force-conflicts only works with --server-side")
	}

	if o.ApplyOptions.DryRunStrategy == cmdutil.DryRunClient && o.ApplyOptions.ServerSideApply {
		return fmt.Errorf("--dry-run=client doesn't work with --server-side (did you mean --dry-run=server instead?)")
	}

	// allow for a success message operation to be specified at print time
	o.ApplyOptions.ToPrinter = func(operation string) (printers.ResourcePrinter, error) {
		o.PrintFlags.NamePrintFlags.Operation = operation
		cmdutil.PrintFlagsWithDryRunStrategy(o.PrintFlags, o.ApplyOptions.DryRunStrategy)
		return o.PrintFlags.ToPrinter()
	}

	// RecordFlags
	// DeleteFlags

	o.ApplyOptions.DeleteOptions = &delete.DeleteOptions{FilenameOptions: resource.FilenameOptions{Filenames: []string{filename}}}

	o.ApplyOptions.OpenAPISchema, _ = f.OpenAPISchema()
	validationDirective, err := cmdutil.GetValidationDirective(cmd)
	if err != nil {
		return err
	}
	o.ApplyOptions.Validator, err = f.Validator(validationDirective)
	if err != nil {
		return err
	}
	o.ApplyOptions.Builder = f.NewBuilder()
	o.ApplyOptions.Mapper, err = f.ToRESTMapper()
	if err != nil {
		return err
	}

	o.ApplyOptions.Namespace, o.ApplyOptions.EnforceNamespace, err = f.ToRawKubeConfigLoader().Namespace()
	if err != nil {
		return err
	}

	o.ApplyOptions.PostProcessorFn = o.ApplyOptions.PrintAndPrunePostProcessor()
	return nil
}

func (o *KubectlOptions) Apply(filename string) error {
	return o.ApplyOptions.Run()
}
