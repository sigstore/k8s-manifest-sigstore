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

package kubeutil

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var cfg *rest.Config

func GetInClusterConfig() (*rest.Config, error) {
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return config, nil
}

func IsInCluster() bool {
	_, err := rest.InClusterConfig()
	if err == nil {
		return true
	} else {
		return false
	}
}

func GetOutOfClusterConfig() (*rest.Config, error) {
	kubeconfigPath := os.Getenv("KUBECONFIG")
	if kubeconfigPath == "" {
		home := os.Getenv("HOME")
		if home == "" {
			home = os.Getenv("USERPROFILE")
		}
		kubeconfigPath = filepath.Join(home, ".kube", "config")
	}
	config, err := clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	if err != nil {
		return nil, err
	}
	return config, nil
}

func GetKubeConfig() (*rest.Config, error) {
	if cfg != nil {
		return cfg, nil
	}
	config, err := GetInClusterConfig()
	if err != nil || config == nil {
		config, err = GetOutOfClusterConfig()
	}
	if err != nil || config == nil {
		return nil, err
	}
	return config, nil
}

func SetKubeConfig(conf *rest.Config) {
	if conf != nil {
		cfg = conf
	}
	return
}

func MatchLabels(obj metav1.Object, labelSelector *metav1.LabelSelector) (bool, error) {
	selector, err := metav1.LabelSelectorAsSelector(labelSelector)
	if err != nil {
		return false, err
	}
	labelsMap := obj.GetLabels()
	labelsSet := labels.Set(labelsMap)
	matched := selector.Matches(labelsSet)
	return matched, nil
}

func GetAPIResources() ([]metav1.APIResource, error) {
	config, err := GetKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("Error in getting k8s config; %s", err.Error())
	}
	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("Error in creating discovery client; %s", err.Error())
	}

	apiResourceLists, err := discoveryClient.ServerPreferredResources()
	if err != nil {
		return nil, fmt.Errorf("Error in getting server preferred resources; %s", err.Error())
	}

	resources := []metav1.APIResource{}
	for _, apiResourceList := range apiResourceLists {
		if len(apiResourceList.APIResources) == 0 {
			continue
		}
		gv, err := schema.ParseGroupVersion(apiResourceList.GroupVersion)
		if err != nil {
			continue
		}
		for _, resource := range apiResourceList.APIResources {
			if len(resource.Verbs) == 0 {
				continue
			}
			resource.Group = gv.Group
			resource.Version = gv.Version
			resources = append(resources, resource)
		}
	}
	return resources, nil
}

func GetResource(apiVersion, kind, namespace, name string) (*unstructured.Unstructured, error) {
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return nil, fmt.Errorf("Error in parsing apiVersion; %s", err.Error())
	}
	apiResources, err := GetAPIResources()
	if err != nil {
		return nil, fmt.Errorf("Error in getting API Resources; %s", err.Error())
	}
	namespaced := true
	gvr := schema.GroupVersionResource{}
	for _, r := range apiResources {
		gOk := (r.Group == gv.Group)
		vOk := (r.Version == gv.Version)
		kOk := (r.Kind == kind)
		if gOk && vOk && kOk {
			gvr = schema.GroupVersionResource{
				Group:    r.Group,
				Version:  r.Version,
				Resource: r.Name,
			}
			namespaced = r.Namespaced
		}
	}
	if gvr.Resource == "" {
		return nil, fmt.Errorf("Failed to find GroupVersionKind matches apiVerions: %s, kind: %s", apiVersion, kind)
	}

	config, err := GetKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("Error in getting k8s config; %s", err.Error())
	}

	dyClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("Error in creating DynamicClient; %s", err.Error())
	}

	var resource *unstructured.Unstructured
	if namespaced {
		resource, err = dyClient.Resource(gvr).Namespace(namespace).Get(context.Background(), name, metav1.GetOptions{})
	} else {
		resource, err = dyClient.Resource(gvr).Get(context.Background(), name, metav1.GetOptions{})
	}
	if err != nil {
		return nil, fmt.Errorf("Error in getting resource; %s", err.Error())
	}
	return resource, nil
}

func ListResources(apiVersion, kind, namespace string) ([]*unstructured.Unstructured, error) {
	gv, err := schema.ParseGroupVersion(apiVersion)
	if err != nil {
		return nil, fmt.Errorf("Error in parsing apiVersion; %s", err.Error())
	}
	apiResources, err := GetAPIResources()
	if err != nil {
		return nil, fmt.Errorf("Error in getting API Resources; %s", err.Error())
	}
	namespaced := true
	gvr := schema.GroupVersionResource{}
	for _, r := range apiResources {
		gOk := (r.Group == gv.Group)
		vOk := (r.Version == gv.Version)
		kOk := (r.Kind == kind)
		if gOk && vOk && kOk {
			gvr = schema.GroupVersionResource{
				Group:    r.Group,
				Version:  r.Version,
				Resource: r.Name,
			}
			namespaced = r.Namespaced
		}
	}
	if gvr.Resource == "" {
		return nil, fmt.Errorf("Failed to find GroupVersionKind matches apiVerions: %s, kind: %s", apiVersion, kind)
	}

	config, err := GetKubeConfig()
	if err != nil {
		return nil, fmt.Errorf("Error in getting k8s config; %s", err.Error())
	}

	dyClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("Error in creating DynamicClient; %s", err.Error())
	}

	var resourceList *unstructured.UnstructuredList
	if namespaced {
		resourceList, err = dyClient.Resource(gvr).Namespace(namespace).List(context.Background(), metav1.ListOptions{})
	} else {
		resourceList, err = dyClient.Resource(gvr).List(context.Background(), metav1.ListOptions{})
	}
	if err != nil {
		return nil, fmt.Errorf("Error in getting resource; %s", err.Error())
	}
	resources := []*unstructured.Unstructured{}
	for i := range resourceList.Items {
		res := resourceList.Items[i]
		resources = append(resources, &res)
	}
	return resources, nil
}
