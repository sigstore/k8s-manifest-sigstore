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
package mapnode

import (
	"encoding/json"
	"io/ioutil"
	"testing"
)

func TestNode(t *testing.T) {

	testMapBytes, _ := ioutil.ReadFile("testdata/data1.json")
	testMap2Bytes, _ := ioutil.ReadFile("testdata/data2.json")
	testMap4Bytes, _ := ioutil.ReadFile("testdata/data3.json")
	deployOperatorBytes, _ := ioutil.ReadFile("testdata/data4.json")

	mergeTestByte := []byte(`{"metadata":{"name":"test-resource"}}`)
	mergeTestByte2 := []byte(`{"metadata":{"namespace":"test-ns"}}`)

	var testMap map[string]interface{}
	json.Unmarshal(testMapBytes, &testMap)
	testNode, _ := NewFromMap(testMap)

	var testMap2 map[string]interface{}
	json.Unmarshal(testMap2Bytes, &testMap2)
	testNode2, _ := NewFromMap(testMap2)

	whitelist := []string{
		"metadata.ownerReferences",
		"metadata.labels",
	}

	containers, _ := testNode.GetNode("spec.containers")
	containersJSON := containers.ToJson()

	maskedMetadata, _ := testNode.Mask(whitelist).GetNode("metadata")
	maskedMetaJSON := maskedMetadata.ToJson()

	dr := testNode.Diff(testNode2)
	drb, _ := json.Marshal(dr)

	maskedNode := testNode.Mask(dr.Keys())
	maskedNode2 := testNode.Mask(dr.Keys())

	dr2 := maskedNode.Diff(maskedNode2)
	drb2, _ := json.Marshal(dr2)

	dr3 := testNode.FindUpdatedAndDeleted(testNode2)
	drb3, _ := json.Marshal(dr3)

	testNode4, _ := NewFromBytes(testMap4Bytes)
	testNode4JSON := testNode4.ToJson()
	// t.Log("8,", testNode4JSON)
	flatTestNode4 := testNode4.Ravel()
	flatJson, _ := json.Marshal(flatTestNode4)
	// t.Log("9,", string(flatJson))

	keepKeys := []string{
		"key1.key11",
		"key2.1",
	}
	keepNode4 := testNode4.Extract(keepKeys)
	keepNode4JSON := keepNode4.ToJson()
	// t.Log("10,", keepNode4JSON)

	jsonpathKeys := []string{
		"$.spec.containers[?(@.name == sample-go-operator)]",
	}
	foundContainer, _ := testNode.GetNodeByJSONPath(jsonpathKeys[0])
	// t.Log("11,", foundContainer)

	deployOperatorNode, _ := NewFromBytes(deployOperatorBytes)
	nodeList := deployOperatorNode.MultipleSubNode("spec.template.spec.containers[].env[]")
	nodeListStr := ""
	for _, node := range nodeList {
		nodeListStr += node.ToJson() + "\n"
	}
	// t.Log("12,", nodeListStr)

	dotKeyValue := deployOperatorNode.GetString("metadata.annotations.\"kubernetes.io/createdby\"")
	// t.Log("13,", dotKeyValue)

	envNode, _ := deployOperatorNode.GetNode("spec.template.spec.containers[0].env")
	// t.Log("14,", envNode)

	keepKeys2 := []string{
		"spec.template.spec.containers",
		"metadata.annotations.\"kubernetes.io/createdby\"",
	}
	mask2 := []string{
		"spec.template.spec.containers[0].env[1]",
		"spec.template.spec.containers[].env[2]",
	}
	maskedEnvNode := deployOperatorNode.Extract(keepKeys2).Mask(mask2)
	wildcardMasked := deployOperatorNode.Mask([]string{"metadata.annotations.\"kubernetes.io/*\""}).SubNode("metadata.annotations")

	nodewithNil := emptyNode()
	nodeWithNilJson := nodewithNil.ToJson()

	mergeTestNode, _ := NewFromBytes(mergeTestByte)
	mergeTestNode2, _ := NewFromBytes(mergeTestByte2)
	mergedNode, err := mergeTestNode.Merge(mergeTestNode2)
	if err != nil {
		t.Log(err)
	}

	nodeWrongType1, _ := NewFromBytes([]byte(`{"testdata":{"key1":"val1","key2":"val2"}}`))
	nodeWrongType2, _ := NewFromBytes([]byte(`{"testdata":{"key1":"val1","key2":123}}`))
	drWrongType := nodeWrongType1.Diff(nodeWrongType2)

	listNode1, _ := NewFromBytes([]byte(`{"listkey":[{"key1":"val1"},{"key2":"val2"},{"key3":"val3"},{"key4":"val4"},{"key5":"val5"}]}`))
	listNode2, _ := NewFromBytes([]byte(`{"listkey":[{"key2":"val2"},{"key3":"val3"},{"key4":"val4"},{"key5":"val5"}]}`))
	drListNode := listNode1.Diff(listNode2)

	e := make(map[int]interface{})
	e[1] = string(`[{"command":["sample-go-operator"],"env":[{"name":"WATCH_NAMESPACE","valueFrom":{"fieldRef":{"apiVersion":"v1","fieldPath":"metadata.namespace"}}},{"name":"POD_NAME","valueFrom":{"fieldRef":{"apiVersion":"v1","fieldPath":"metadata.name"}}},{"name":"OPERATOR_NAME","value":"sample-go-operator"}],"image":"sample-go-operator:local","imagePullPolicy":"IfNotPresent","name":"sample-go-operator","resources":{},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","volumeMounts":[{"mountPath":"/var/run/secrets/kubernetes.io/serviceaccount","name":"sample-go-operator-token-lxn92","readOnly":true}]}]`)
	e[2] = string(`{"creationTimestamp":"2020-03-09T05:19:11Z","generateName":"sample-go-operator-b8bb6c748-","name":"sample-go-operator-b8bb6c748-vz2m8","namespace":"test-go-operator"}`)
	e[3] = string(`{"items":[{"key":"metadata.resourceVersion","values":{"after":"402534","before":null}},{"key":"metadata.selfLink","values":{"after":"/api/v1/namespaces/test-go-operator/pods/sample-go-operator-b8bb6c748-vz2m8","before":null}},{"key":"metadata.uid","values":{"after":"6885d94e-6fd1-40c8-847b-85fcf00abbdc","before":null}},{"key":"spec.containers.0.imagePullPolicy","values":{"after":"Always","before":"IfNotPresent"}},{"key":"spec.securityContext.privileged","values":{"after":true,"before":null}}]}`)
	e[4] = string(`null`)
	e[5] = string(`{"items":[{"key":"spec.containers.0.imagePullPolicy","values":{"after":"Always","before":"IfNotPresent"}}]}`)
	e[6] = string(`{"key1":{"key11":{"key111":"val111","key112":"val112"},"key12":{"key121":"val121","key122":"val122","key123":"val123"}},"key2":[{"key21":"val21"},{"key22":"val22"}]}`)
	e[7] = string(`{"key1.key11.key111":"val111","key1.key11.key112":"val112","key1.key12.key121":"val121","key1.key12.key122":"val122","key1.key12.key123":"val123","key2.0.key21":"val21","key2.1.key22":"val22"}`)
	e[8] = string(`{"key1":{"key11":{"key111":"val111","key112":"val112"}},"key2":[{"key22":"val22"}]}`)
	e[9] = string(`[{"command":["sample-go-operator"],"env":[{"name":"WATCH_NAMESPACE","valueFrom":{"fieldRef":{"apiVersion":"v1","fieldPath":"metadata.namespace"}}},{"name":"POD_NAME","valueFrom":{"fieldRef":{"apiVersion":"v1","fieldPath":"metadata.name"}}},{"name":"OPERATOR_NAME","value":"sample-go-operator"}],"image":"sample-go-operator:local","imagePullPolicy":"IfNotPresent","name":"sample-go-operator","resources":{},"terminationMessagePath":"/dev/termination-log","terminationMessagePolicy":"File","volumeMounts":[{"mountPath":"/var/run/secrets/kubernetes.io/serviceaccount","name":"sample-go-operator-token-lxn92","readOnly":true}]}]`)
	e[10] = string(`{"name":"WATCH_NAMESPACE","valueFrom":{"fieldRef":{"fieldPath":"metadata.namespace"}}}
{"name":"POD_NAME","valueFrom":{"fieldRef":{"fieldPath":"metadata.name"}}}
{"name":"OPERATOR_NAME","value":"sample-operator"}
`)
	e[11] = string(`openshift.io/dockercfg-hoge-fuga`)
	e[12] = string(`[{"name":"WATCH_NAMESPACE","valueFrom":{"fieldRef":{"fieldPath":"metadata.namespace"}}},{"name":"POD_NAME","valueFrom":{"fieldRef":{"fieldPath":"metadata.name"}}},{"name":"OPERATOR_NAME","value":"sample-operator"}]`)
	e[13] = string(`metadata:
  annotations:
    kubernetes.io/createdby: openshift.io/dockercfg-hoge-fuga
spec:
  template:
    spec:
      containers:
      - env:
        - name: WATCH_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        image: sampleregistry/sample-operator:dev
        imagePullPolicy: Always
        name: sample-operator
`)
	e[14] = string(`{"signPaths":"apiVersion,kind,metadata.name,spec.template.spec.containers[].env[]"}`)
	e[15] = string(`null`)
	e[16] = string(`{"metadata":{"name":"test-resource","namespace":"test-ns"}}`)
	e[17] = string(`{"items":[{"key":"testdata.key2","values":{"after":"(type: float64) %!s(float64=123)","before":"(type: string) val2"}}]}`)
	e[18] = string(`{"items":[{"key":"listkey.0.key1","values":{"after":null,"before":"val1"}}]}`)

	a := make(map[int]interface{})
	a[1] = string(containersJSON)
	a[2] = string(maskedMetaJSON)
	a[3] = string(drb)
	a[4] = string(drb2)
	a[5] = string(drb3)
	a[6] = string(testNode4JSON)
	a[7] = string(flatJson)
	a[8] = string(keepNode4JSON)
	a[9] = string(foundContainer.String())
	a[10] = string(nodeListStr)
	a[11] = string(dotKeyValue)
	a[12] = string(envNode.ToJson())
	a[13] = string(maskedEnvNode.ToYaml())
	a[14] = string(wildcardMasked.ToJson())
	a[15] = string(nodeWithNilJson)
	a[16] = string(mergedNode.ToJson())
	a[17] = string(drWrongType.String())
	a[18] = string(drListNode.String())

	for i := range e {
		if a[i] != e[i] {
			t.Errorf("pattern %d:", i)
			t.Errorf("\texpect: %d", e[i])
			t.Errorf("\tactual: %d", a[i])
		}
	}

}
