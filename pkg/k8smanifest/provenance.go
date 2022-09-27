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

package k8smanifest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/go-openapi/runtime"
	cliopt "github.com/sigstore/cosign/cmd/cosign/cli/options"
	cremote "github.com/sigstore/cosign/pkg/oci/remote"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	intoto "github.com/in-toto/in-toto-golang/in_toto"
	intotoprov02 "github.com/in-toto/in-toto-golang/in_toto/slsa_provenance/v0.2"
	k8scosign "github.com/sigstore/k8s-manifest-sigstore/pkg/cosign"
	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	kubeutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	"github.com/sigstore/rekor/pkg/client"
	genclient "github.com/sigstore/rekor/pkg/generated/client"
	"github.com/sigstore/rekor/pkg/generated/client/entries"
	"github.com/sigstore/rekor/pkg/generated/client/index"
	"github.com/sigstore/rekor/pkg/generated/models"
	"github.com/sigstore/rekor/pkg/types"
	_ "github.com/sigstore/rekor/pkg/types/intoto/v0.0.1"
	rekorutil "github.com/sigstore/rekor/pkg/util"
	tektonchainsprov "github.com/tektoncd/chains/pkg/chains/provenance"
)

type ArtifactType string

const (
	ArtifactUnknown          = ""
	ArtifactManifestImage    = "manifestImage"
	ArtifactManifestResource = "manifestResource"
	ArtifactContainerImage   = "containerImage"
)

const (
	AttestationDataKeyName = "attestation"
	SBOMDataKeyName        = "sbom"
)

type Provenance struct {
	ResourceName *resourceName `json:"resource"`

	RawAttestation string `json:"rawAttestation"`
	RawSBOM        string `json:"rawSBOM"`

	Artifact             string               `json:"artifact"`
	ArtifactType         ArtifactType         `json:"artifactType"`
	Hash                 string               `json:"hash"`
	AttestationLogIndex  *int                 `json:"attestationLogIndex"`
	AttestationMaterials []ProvenanceMaterial `json:"attestationMaterials"`

	SBOMRef string `json:"sbom"`

	ConfigMapRef string `json:"configMapRef"`
}

type resourceName struct {
	PodName       string `json:"podName"`
	ContainerName string `json:"containerName"`
}

type ProvenanceGetter interface {
	Get() ([]*Provenance, error)
}

func NewProvenanceGetter(obj *unstructured.Unstructured, sigRef, imageHash, provResRef string) ProvenanceGetter {
	var resBundleRef string
	if !strings.HasPrefix(sigRef, kubeutil.InClusterObjectPrefix) {
		resBundleRef = sigRef
	}

	if obj != nil {
		return &RecursiveImageProvenanceGetter{object: obj, manifestResourceBundleRef: resBundleRef, manifestProvenanceResourceRef: provResRef, cacheEnabled: true}
	} else if resBundleRef != "" && resBundleRef != SigRefEmbeddedInAnnotation {
		return &ImageProvenanceGetter{resBundleRef: resBundleRef, imageHash: imageHash, cacheEnabled: true}
	} else if provResRef != "" {
		return &ResourceProvenanceGetter{resourceRefString: provResRef}
	} else {
		return &NotImplementedProvenanceGetter{}
	}
}

type RecursiveImageProvenanceGetter struct {
	object                        *unstructured.Unstructured
	manifestResourceBundleRef     string
	manifestProvenanceResourceRef string
	cacheEnabled                  bool
}

func (g *RecursiveImageProvenanceGetter) Get() ([]*Provenance, error) {

	provs := []*Provenance{}
	// manifest provenance
	if g.manifestResourceBundleRef != "" {
		// manifest prov from image
		log.Trace("manifest provenance imageDigest")
		digest, err := g.imageDigest(g.manifestResourceBundleRef)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get manifest image digest")
		}
		log.Trace("manifest image provenance getter")
		imgGetter := NewProvenanceGetter(nil, g.manifestResourceBundleRef, digest, "")
		prov, err := imgGetter.Get()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get manifest image provenance")
		}
		for _, p := range prov {
			p.ArtifactType = ArtifactManifestImage
			provs = append(provs, p)
		}
	} else if g.manifestProvenanceResourceRef != "" {
		// manifest prov from resource
		log.Trace("manifest resource provenance getter")
		resGetter := NewProvenanceGetter(nil, "", "", g.manifestProvenanceResourceRef)
		prov, err := resGetter.Get()
		if err != nil {
			return nil, errors.Wrap(err, "failed to get manifest resource provenance")
		}
		for _, p := range prov {
			p.ArtifactType = ArtifactManifestResource
			provs = append(provs, p)
		}
	}

	// container images from this object
	if g.object != nil {
		provsFromObject := []*Provenance{}
		log.Trace("object provenance load")
		images, err := kubeutil.GetAllImagesFromObject(g.object)
		if err != nil {
			return nil, err
		}

		sumErr := []string{}
		for _, img := range images {
			log.Trace("object provenance getter for image:", img.ResourceBundleRef)
			imgGetter := NewProvenanceGetter(nil, img.ResourceBundleRef, img.Digest, "")
			prov, err := imgGetter.Get()
			if err != nil {
				sumErr = append(sumErr, err.Error())
				continue
			}
			for _, p := range prov {
				p.ArtifactType = ArtifactContainerImage
				p.ResourceName = &resourceName{
					PodName:       img.PodName,
					ContainerName: img.ContainerName,
				}
				provsFromObject = append(provsFromObject, p)
			}
		}
		if len(provsFromObject) == 0 && len(sumErr) > 0 {
			return nil, fmt.Errorf("failed to get provenance for this object: %s", strings.Join(sumErr, "; "))
		}
		provs = append(provs, provsFromObject...)
	}

	return provs, nil
}

func (g *RecursiveImageProvenanceGetter) imageDigest(resBundleRef string) (string, error) {
	resultsNum := 2
	cacheKey := fmt.Sprintf("RecursiveImageProvenanceGetter/imageDigest/%s", g.manifestResourceBundleRef)
	digest := ""
	var err error
	if g.cacheEnabled {

		results, cacheErr := k8smnfutil.GetCache(cacheKey)
		cacheFound := false
		if len(results) != resultsNum && cacheErr == nil {
			return "", fmt.Errorf("the number of results is wrong, GetImageDigest() should return %v, got %v", resultsNum, len(results))
		} else if len(results) == resultsNum && cacheErr == nil {
			cacheFound = true
		}

		if cacheFound {
			if results[0] != nil {
				digest = results[0].(string)
			}
			if results[1] != nil {
				err = results[1].(error)
			}
		} else {
			log.Debug("image digest cache not found for image: ", resBundleRef)
			digest, err = k8smnfutil.GetImageDigest(g.manifestResourceBundleRef)
			err = k8smnfutil.SetCache(cacheKey, digest, err)
			if err != nil {
				log.Debug("failed to set image digest cache")
			}
		}
	} else {
		digest, err = k8smnfutil.GetImageDigest(g.manifestResourceBundleRef)
	}
	if err != nil {
		return "", errors.Wrap(err, "failed to get manifest image digest")
	}
	return digest, nil
}

type ImageProvenanceGetter struct {
	resBundleRef string
	imageHash    string
	cacheEnabled bool
}

func (g *ImageProvenanceGetter) Get() ([]*Provenance, error) {
	sumErr := []string{}
	log.Trace("ImageProvenanceGetter getAttestation()")
	attestation, attestationLogIndex, err := g.getAttestation()
	if err != nil {
		log.Debug("getAttestation() error for image: ", g.resBundleRef, ", error: ", err.Error())
		sumErr = append(sumErr, err.Error())
	}
	materials := []ProvenanceMaterial{}
	if attestation != nil {
		_, _, materials, _ = ParseAttestation(string(attestation))
	}
	log.Trace("ImageProvenanceGetter getSBOM()")
	sbom, err := g.getSBOM()
	if err != nil {
		log.Debug("getSBOM() error for image: ", g.resBundleRef, ", error: ", err.Error())
		sumErr = append(sumErr, err.Error())
	}
	if attestation == nil && sbom == "" && len(sumErr) > 0 {
		return nil, fmt.Errorf("no provenance data fonud: %s", strings.Join(sumErr, "; "))
	}
	p := &Provenance{
		RawAttestation:       string(attestation),
		Artifact:             g.resBundleRef,
		Hash:                 g.imageHash,
		AttestationLogIndex:  attestationLogIndex,
		AttestationMaterials: materials,
		SBOMRef:              sbom,
	}
	return []*Provenance{p}, nil
}

func (g *ImageProvenanceGetter) getAttestation() ([]byte, *int, error) {

	var attestationBytes []byte
	var attestationLogIndex *int
	var err error
	if g.cacheEnabled {
		cacheKey := fmt.Sprintf("ImageProvenanceGetter/getAttestationEntry/%s", g.imageHash)
		resultsNum := 3
		results, cacheErr := k8smnfutil.GetCache(cacheKey)
		cacheFound := false
		if len(results) != resultsNum && cacheErr == nil {
			return nil, nil, fmt.Errorf("the number of results is wrong, getAttestationEntry() should return %v, got %v", resultsNum, len(results))
		} else if len(results) == resultsNum && cacheErr == nil {
			cacheFound = true
		}

		if cacheFound {
			if results[0] != nil {
				var ok bool
				if attestationBytes, ok = results[0].([]byte); !ok {
					attestationStr := results[0].(string)
					if tmpBytes, err := base64.StdEncoding.DecodeString(attestationStr); err == nil {
						attestationBytes = tmpBytes
					}
				}
			}
			if results[1] != nil {
				var ok bool
				if attestationLogIndex, ok = results[1].(*int); !ok {
					attestationLogFloat := results[1].(float64)
					attestationLogInt := int(attestationLogFloat)
					attestationLogIndex = &attestationLogInt
				}
			}
			if results[2] != nil {
				var ok bool
				if err, ok = results[2].(error); !ok {
					errMap := results[2].(map[string]interface{})
					if errBytes, mErr := json.Marshal(errMap); mErr == nil {
						err = errors.New(string(errBytes))
					}
				}
			}
		} else {
			log.Debug("attestation cache not found for image: ", g.resBundleRef, ", hash: ", g.imageHash)
			attestationBytes, attestationLogIndex, err = getAttestationEntry(g.imageHash)
			err = k8smnfutil.SetCache(cacheKey, attestationBytes, attestationLogIndex, err)
			if err != nil {
				log.Debug("failed to set attestation cache")
			}
		}
	} else {
		attestationBytes, attestationLogIndex, err = getAttestationEntry(g.imageHash)
	}
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to get attestation data")
	}
	return attestationBytes, attestationLogIndex, nil
}

func (g *ImageProvenanceGetter) getSBOM() (string, error) {
	sbomRef := ""
	var err error
	if g.cacheEnabled {
		cacheKey := fmt.Sprintf("ImageProvenanceGetter/getSBOMRef/%s", g.resBundleRef)
		resultsNum := 2
		results, cacheErr := k8smnfutil.GetCache(cacheKey)
		cacheFound := false
		if len(results) != resultsNum && cacheErr == nil {
			return "", fmt.Errorf("the number of results is wrong, getSBOMRef() should return %v, got %v", resultsNum, len(results))
		} else if len(results) == resultsNum && cacheErr == nil {
			cacheFound = true
		}

		if cacheFound {
			if results[0] != nil {
				sbomRef = results[0].(string)
			}
			if results[1] != nil {
				var ok bool
				if err, ok = results[1].(error); !ok {
					errMap := results[1].(map[string]interface{})
					if errBytes, mErr := json.Marshal(errMap); mErr == nil {
						err = errors.New(string(errBytes))
					}
				}
			}
		} else {
			log.Debug("sbom reference cache not found for image: ", g.resBundleRef)
			sbomRef, err = g.getSBOMRef(g.resBundleRef)
			err = k8smnfutil.SetCache(cacheKey, sbomRef, err)
			if err != nil {
				log.Debug("failed to set sbom reference cache")
			}
		}
	} else {
		sbomRef, err = g.getSBOMRef(g.resBundleRef)
	}
	if err != nil {
		return "", errors.Wrap(err, "failed to get sbom")
	}
	return sbomRef, nil
}

func (g *ImageProvenanceGetter) getSBOMRef(resBundleRef string) (string, error) {
	ref, err := name.ParseReference(resBundleRef)
	if err != nil {
		return "", err
	}
	regOpt := &cliopt.RegistryOptions{}
	reqCliOpt := regOpt.GetRegistryClientOpts(context.Background())
	dstRef, err := cremote.SBOMTag(ref, cremote.WithRemoteOptions(reqCliOpt...))
	if err != nil {
		return "", err
	}

	auth := remote.WithAuthFromKeychain(authn.DefaultKeychain)
	_, err = remote.Get(dstRef, auth)
	if err != nil {
		return "", err
	}
	return dstRef.String(), nil
}

type ResourceProvenanceGetter struct {
	resourceRefString string
}

func (g *ResourceProvenanceGetter) Get() ([]*Provenance, error) {
	resourceRefString := g.resourceRefString
	if resourceRefString == "" {
		return nil, errors.New("no signature resource reference is specified")
	}

	provList := []*Provenance{}
	resourceRefList := k8smnfutil.SplitCommaSeparatedString(resourceRefString)
	for _, resourceRef := range resourceRefList {
		prov, err := g.getProvenanceInSingleConfigMap(resourceRef)
		if err != nil {
			return nil, err
		}
		provList = append(provList, prov)
	}
	return provList, nil
}

func (g *ResourceProvenanceGetter) getProvenanceInSingleConfigMap(singleCMRef string) (*Provenance, error) {
	cm, err := GetConfigMapFromK8sObjectRef(singleCMRef)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get a configmap")
	}
	base64atst, atstFound := cm.Data[AttestationDataKeyName]
	base64sbom, sbomFound := cm.Data[SBOMDataKeyName]
	if !atstFound && !sbomFound {
		return nil, fmt.Errorf("no fields named `%s` and `%s`", AttestationDataKeyName, SBOMDataKeyName)
	}
	var atstBytes, sbomBytes []byte
	if atstFound {
		atstBytes, err = base64.StdEncoding.DecodeString(base64atst)
		if err != nil {
			return nil, errors.Wrap(err, "failed to base64 decode the found attestation")
		}
	}
	if sbomFound {
		sbomBytes, err = base64.StdEncoding.DecodeString(base64sbom)
		if err != nil {
			return nil, errors.Wrap(err, "failed to base64 decode the found sbom")
		}
	}
	var statement *intoto.Statement
	materials := []ProvenanceMaterial{}
	if atstBytes != nil {
		statement, _, materials, _ = ParseAttestation(string(atstBytes))
	}
	var artifact string
	var artifactHash string

	if statement != nil && len(statement.Subject) > 0 {
		artifact = statement.Subject[0].Name
		artifactHash = statement.Subject[0].Digest["sha256"]
	}
	prov := &Provenance{
		RawAttestation:       string(atstBytes),
		RawSBOM:              string(sbomBytes),
		Artifact:             artifact,
		Hash:                 artifactHash,
		AttestationMaterials: materials,
		ConfigMapRef:         singleCMRef,
	}
	return prov, nil
}

type NotImplementedProvenanceGetter struct {
}

func (g *NotImplementedProvenanceGetter) Get() ([]*Provenance, error) {
	return nil, fmt.Errorf("provenance getter for this object is not implemented yet")
}

func getAttestationEntry(hash string) ([]byte, *int, error) {
	rekorServerURL := k8scosign.GetRekorServerURL()
	rekorClient, err := client.GetRekorClient(rekorServerURL)
	if err != nil {
		return nil, nil, err
	}

	// search tlog uuid by hash
	params1 := index.NewSearchIndexParams()
	params1.Query = &models.SearchIndex{
		Hash: hash,
	}

	resp1, err := rekorClient.Index.SearchIndex(params1)
	if err != nil {
		switch t := err.(type) {
		case *index.SearchIndexDefault:
			if t.Code() == http.StatusNotImplemented {
				return nil, nil, fmt.Errorf("search index not enabled on %v", rekorServerURL)
			}
			return nil, nil, err
		default:
			return nil, nil, err
		}
	}
	uuids := resp1.GetPayload()
	if len(uuids) == 0 {
		return nil, nil, fmt.Errorf("attestation transparency log not found for hash: %s", hash)
	}

	// get tlog by uuid
	uuid := uuids[0]

	params2 := entries.NewGetLogEntryByUUIDParams()
	params2.EntryUUID = uuid

	resp2, err := rekorClient.Entries.GetLogEntryByUUID(params2)
	if err != nil {
		return nil, nil, err
	}

	for k, entry := range resp2.Payload {
		if k != uuid {
			continue
		}

		if verified, err := verifyLogEntry(context.Background(), rekorClient, entry); err != nil || !verified {
			return nil, nil, fmt.Errorf("unable to verify entry was added to log %w", err)
		}

		attestationEntry, err := parseEntry(k, entry)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse entry of tlog %w", err)
		}
		if attestationEntry.Attestation == "" {
			return nil, nil, fmt.Errorf("no attestation found in tlog %w", err)
		}
		var decodedAttestation []byte
		decodedAttestation, err = base64.StdEncoding.DecodeString(attestationEntry.Attestation)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decode base64 encoded attestation %w", err)
		}
		attestationLogIndexNum := attestationEntry.LogIndex
		return decodedAttestation, &attestationLogIndexNum, nil
	}
	return nil, nil, fmt.Errorf("attestation transparancy log not found for uuid: %s", uuid)
}

func verifyLogEntry(ctx context.Context, rekorClient *genclient.Rekor, logEntry models.LogEntryAnon) (bool, error) {
	if logEntry.Verification == nil {
		return false, nil
	}
	// verify the entry
	if logEntry.Verification.SignedEntryTimestamp == nil {
		return false, fmt.Errorf("signature missing")
	}

	le := &models.LogEntryAnon{
		IntegratedTime: logEntry.IntegratedTime,
		LogIndex:       logEntry.LogIndex,
		Body:           logEntry.Body,
		LogID:          logEntry.LogID,
	}

	payload, err := le.MarshalBinary()
	if err != nil {
		return false, err
	}
	canonicalized, err := jsoncanonicalizer.Transform(payload)
	if err != nil {
		return false, err
	}

	// get rekor's public key
	rekorPubKey, err := rekorutil.PublicKey(ctx, rekorClient)
	if err != nil {
		return false, err
	}

	// verify the SET against the public key
	hash := sha256.Sum256(canonicalized)
	if !ecdsa.VerifyASN1(rekorPubKey, hash[:], []byte(logEntry.Verification.SignedEntryTimestamp)) {
		return false, fmt.Errorf("unable to verify")
	}
	return true, nil
}

func parseEntry(uuid string, e models.LogEntryAnon) (*rekorCLIGetCmdOutput, error) {
	b, err := base64.StdEncoding.DecodeString(e.Body.(string))
	if err != nil {
		return nil, err
	}

	pe, err := models.UnmarshalProposedEntry(bytes.NewReader(b), runtime.JSONConsumer())
	if err != nil {
		return nil, err
	}
	eimpl, err := types.UnmarshalEntry(pe)
	if err != nil {
		return nil, err
	}

	obj := &rekorCLIGetCmdOutput{
		Attestation:    string(e.Attestation.Data),
		Body:           eimpl,
		UUID:           uuid,
		IntegratedTime: *e.IntegratedTime,
		LogIndex:       int(*e.LogIndex),
		LogID:          *e.LogID,
	}

	return obj, nil
}

type rekorCLIGetCmdOutput struct {
	Attestation     string
	AttestationType string
	Body            interface{}
	LogIndex        int
	IntegratedTime  int64
	UUID            string
	LogID           string
}

type DigestSet map[string]string

type ProvenanceMaterial struct {
	URI    string    `json:"uri"`
	Digest DigestSet `json:"digest,omitempty"`
}

func ParseAttestation(attestationStr string) (*intoto.Statement, interface{}, []ProvenanceMaterial, error) {
	var attestation *intoto.Statement
	err := json.Unmarshal([]byte(attestationStr), &attestation)
	if err != nil {
		return nil, nil, nil, err
	}

	var predicate interface{}
	materials := []ProvenanceMaterial{}
	if attestation.PredicateType == "https://tekton.dev/chains/provenance" {
		predicateBytes, _ := json.Marshal(attestation.Predicate)
		var tmpPred tektonchainsprov.ProvenancePredicate
		err := json.Unmarshal(predicateBytes, &tmpPred)
		if err == nil {
			predicate = &tmpPred
			for _, m := range tmpPred.Materials {
				digest := map[string]string{}
				for k, v := range m.Digest {
					digest[k] = v
				}
				materials = append(materials, ProvenanceMaterial{URI: m.URI, Digest: DigestSet(digest)})
			}
		}
	} else if attestation.PredicateType == intotoprov02.PredicateSLSAProvenance {
		predicateBytes, _ := json.Marshal(attestation.Predicate)
		var tmpPred intotoprov02.ProvenancePredicate
		err := json.Unmarshal(predicateBytes, &tmpPred)
		if err == nil {
			predicate = &tmpPred
			for _, m := range tmpPred.Materials {
				digest := map[string]string{}
				for k, v := range m.Digest {
					digest[k] = v
				}
				materials = append(materials, ProvenanceMaterial{URI: m.URI, Digest: DigestSet(digest)})
			}
		}
	}
	return attestation, predicate, materials, nil
}

func GenerateIntotoAttestationCurlCommand(logIndex int) string {
	rekorServerURL := k8scosign.GetRekorServerURL()
	logIndexStr := strconv.Itoa(logIndex)
	cmdStr := fmt.Sprintf("curl -s \"%s/api/v1/log/entries/?logIndex=%s\"", rekorServerURL, logIndexStr)
	return cmdStr
}

func GenerateIntotoAttestationKubectlCommand(resourceRef string) string {
	kind, ns, name, _ := kubeutil.ParseObjectRefInClusterWithKind(resourceRef)
	cmdStr := fmt.Sprintf("kubectl get %s -n %s %s -o=jsonpath='{.data.%s}'", kind, ns, name, AttestationDataKeyName)
	return cmdStr
}

func GenerateSBOMDownloadCommand(resBundleRef string) string {
	cmdStr := fmt.Sprintf("cosign download sbom %s", resBundleRef)
	return cmdStr
}

func GenerateSBOMKubectlCommand(resourceRef string) string {
	kind, ns, name, _ := kubeutil.ParseObjectRefInClusterWithKind(resourceRef)
	cmdStr := fmt.Sprintf("kubectl get %s -n %s %s -o=jsonpath='{.data.%s}'", kind, ns, name, SBOMDataKeyName)
	return cmdStr
}
