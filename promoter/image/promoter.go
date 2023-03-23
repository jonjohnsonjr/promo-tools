/*
Copyright 2022 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package imagepromoter

//go:generate go run github.com/maxbrunsfeld/counterfeiter/v6 -generate

import (
	"errors"
	"fmt"
	"path"
	"sort"

	"github.com/sirupsen/logrus"

	reg "sigs.k8s.io/promo-tools/v3/internal/legacy/dockerregistry"
	"sigs.k8s.io/promo-tools/v3/internal/legacy/dockerregistry/registry"
	"sigs.k8s.io/promo-tools/v3/internal/legacy/dockerregistry/schema"
	impl "sigs.k8s.io/promo-tools/v3/internal/promoter/image"
	options "sigs.k8s.io/promo-tools/v3/promoter/image/options"
)

var AllowedOutputFormats = []string{
	"csv",
	"yaml",
}

type Promoter struct {
	Options *options.Options
	impl    *impl.DefaultPromoterImplementation
}

func New() *Promoter {
	return &Promoter{
		Options: options.DefaultOptions,
		impl:    impl.NewDefaultPromoterImplementation(),
	}
}

// PromoteImages is the main method for image promotion
// it runs by taking all its parameters from a set of options.
func (p *Promoter) PromoteImages(opts *options.Options) (err error) {
	logrus.Infof("PromoteImages start")

	// Validate the options. Perhaps another image-specific
	// validation function may be needed.
	if err := p.impl.ValidateOptions(opts); err != nil {
		return fmt.Errorf("validating options: %w", err)
	}

	if err := p.impl.ActivateServiceAccounts(opts); err != nil {
		return fmt.Errorf("activating service accounts: %w", err)
	}

	// Prewarm the TUF cache with the targets and keys. This is done
	// to avoid collisions when signing and verifying in parallel
	if err := p.impl.PrewarmTUFCache(); err != nil {
		return fmt.Errorf("prewarming TUF cache: %w", err)
	}

	logrus.Infof("Parsing manifests")
	mfests, err := p.impl.ParseManifests(opts)
	if err != nil {
		return fmt.Errorf("parsing manifests: %w", err)
	}

	p.impl.PrintVersion()
	p.impl.PrintSection("START (PROMOTION)", opts.Confirm)

	MakeSyncContext := func(mfests []schema.Manifest, threads int, confirm, useSvcAcc bool) (*reg.SyncContext, error) {
		sc := reg.SyncContext{
			Threads:           threads,
			Confirm:           confirm,
			UseServiceAccount: useSvcAcc,
			Inv:               make(reg.MasterInventory),
			InvIgnore:         []string{},
			RegistryContexts:  make([]registry.Context, 0),
			DigestMediaType:   make(reg.DigestMediaType),
			DigestImageSize:   make(reg.DigestImageSize),
			ParentDigest:      make(reg.ParentDigest),
		}

		registriesSeen := make(map[registry.Context]interface{})
		for _, mfest := range mfests {
			for _, r := range mfest.Registries {
				registriesSeen[r] = nil
			}
		}

		// Populate SyncContext with registries found across all manifests.
		for r := range registriesSeen {
			sc.RegistryContexts = append(sc.RegistryContexts, r)
		}

		// Sort the list for determinism. We first sort it alphabetically, then sort
		// it by length (reverse order, so that the longest registry names come
		// first). This is so that we try to match the leading prefix against the
		// longest registry names first. We sort alphabetically first because we
		// want the final order to be deterministic.
		sort.Slice(
			sc.RegistryContexts,
			func(i, j int) bool {
				return sc.RegistryContexts[i].Name < sc.RegistryContexts[j].Name
			},
		)

		sort.Slice(
			sc.RegistryContexts,
			func(i, j int) bool {
				return len(sc.RegistryContexts[i].Name) > len(sc.RegistryContexts[j].Name)
			},
		)

		return &sc, nil
	}

	logrus.Infof("Creating sync context manifests")
	sc, err := MakeSyncContext(mfests, opts.Threads, opts.Confirm, opts.UseServiceAcct)
	if err != nil {
		return fmt.Errorf("creating sync context: %w", err)
	}

	mkPromotionEdge := func(srcRC, dstRC registry.Context, srcImageName string, digest string, tag string) reg.PromotionEdge {
		edge := reg.PromotionEdge{
			SrcRegistry: srcRC,
			SrcImageTag: reg.ImageTag{
				Name: srcImageName,
				Tag:  tag,
			},

			Digest:      digest,
			DstRegistry: dstRC,
		}

		// The name in the destination is the same as the name in the source.
		edge.DstImageTag = reg.ImageTag{
			Name: srcImageName,
			Tag:  tag,
		}

		return edge
	}

	CheckOverlappingEdges := func(edges map[reg.PromotionEdge]interface{}) (map[reg.PromotionEdge]interface{}, error) {
		// Build up a "promotionIntent". This will be checked below.
		promotionIntent := make(map[string]map[string][]reg.PromotionEdge)
		checked := make(map[reg.PromotionEdge]interface{})
		for edge := range edges {
			// Skip overlap checks for edges that are tagless, because by definition
			// they cannot overlap with another edge.
			if edge.DstImageTag.Tag == "" {
				checked[edge] = nil
				continue
			}

			dstPQIN := reg.ToPQIN(edge.DstRegistry.Name,
				edge.DstImageTag.Name,
				edge.DstImageTag.Tag,
			)

			digestToEdges, ok := promotionIntent[dstPQIN]
			if ok {
				// Store the edge.
				digestToEdges[edge.Digest] = append(digestToEdges[edge.Digest], edge)
				promotionIntent[dstPQIN] = digestToEdges
			} else {
				// Make this edge lay claim to this destination vertex.
				edgeList := make([]reg.PromotionEdge, 0)
				edgeList = append(edgeList, edge)
				digestToEdges := make(map[string][]reg.PromotionEdge)
				digestToEdges[edge.Digest] = edgeList
				promotionIntent[dstPQIN] = digestToEdges
			}
		}

		// Review the promotionIntent to ensure that there are no issues.
		overlapError := false
		emptyEdgeListError := false
		for pqin, digestToEdges := range promotionIntent {
			if len(digestToEdges) < 2 {
				for _, edgeList := range digestToEdges {
					switch len(edgeList) {
					case 0:
						logrus.Errorf("no edges for %v", pqin)
						emptyEdgeListError = true
					case 1:
						checked[edgeList[0]] = nil
					default:
						logrus.Infof("redundant promotion: multiple edges want to promote the same digest to the same destination endpoint %v:", pqin)

						// TODO(lint): rangeValCopy: each iteration copies 192 bytes (consider pointers or indexing)
						//nolint:gocritic
						for _, edge := range edgeList {
							logrus.Infof("%v", edge)
						}
						logrus.Infof("using the first one: %v", edgeList[0])
						checked[edgeList[0]] = nil
					}
				}
			} else {
				logrus.Errorf("multiple edges want to promote *different* images (digests) to the same destination endpoint %v:", pqin)
				for digest, edgeList := range digestToEdges {
					logrus.Errorf("  for digest %v:\n", digest)

					// TODO(lint): rangeValCopy: each iteration copies 192 bytes (consider pointers or indexing)
					//nolint:gocritic
					for _, edge := range edgeList {
						logrus.Errorf("%v\n", edge)
					}
				}
				overlapError = true
			}
		}

		if overlapError {
			return nil, fmt.Errorf("overlapping edges detected")
		}

		if emptyEdgeListError {
			return nil, fmt.Errorf("empty edgeList(s) detected")
		}

		return checked, nil
	}

	ToPromotionEdges := func(mfests []schema.Manifest) (map[reg.PromotionEdge]interface{}, error) {
		edges := make(map[reg.PromotionEdge]interface{})
		for _, mfest := range mfests {
			for _, img := range mfest.Images {
				for digest, tagArray := range img.Dmap {
					for _, destRC := range mfest.Registries {
						if destRC == *mfest.SrcRegistry {
							continue
						}

						if len(tagArray) > 0 {
							for _, tag := range tagArray {
								edge := mkPromotionEdge(
									*mfest.SrcRegistry,
									destRC,
									img.Name,
									digest,
									tag)
								edges[edge] = nil
							}
						} else {
							// If this digest does not have any associated tags, still create
							// a promotion edge for it (tagless promotion).
							edge := mkPromotionEdge(
								*mfest.SrcRegistry,
								destRC,
								img.Name,
								digest,
								"",
							)

							edges[edge] = nil
						}
					}
				}
			}
		}

		return CheckOverlappingEdges(edges)
	}

	logrus.Infof("Getting promotion edges")
	// First, get the "edges" from the manifests
	promotionEdges, err := ToPromotionEdges(mfests)
	if err != nil {
		return fmt.Errorf("converting list of manifests to edges for promotion: %w", err)
	}

	getRegistriesToRead := func(edges map[reg.PromotionEdge]interface{}) []registry.Context {
		rcs := make(map[registry.Context]interface{})

		// Save the src and dst endpoints as registries. We only care about the
		// registry and image name, not the tag or digest; this is to collect all
		// unique Docker repositories that we care about.
		for edge := range edges {
			srcReg := edge.SrcRegistry
			srcReg.Name = path.Join(srcReg.Name, edge.SrcImageTag.Name)

			rcs[srcReg] = nil

			dstReg := edge.DstRegistry
			dstReg.Name = path.Join(dstReg.Name, edge.DstImageTag.Name)

			rcs[dstReg] = nil
		}

		rcsFinal := []registry.Context{}
		for rc := range rcs {
			rcsFinal = append(rcsFinal, rc)
		}

		return rcsFinal
	}

	nedges, ok := sc.GetPromotionCandidates(promotionEdges)
	// Run the promotion edge filtering
	regs := getRegistriesToRead(nedges)
	for _, reg := range regs {
		logrus.Infof("reading registry %s (src=%v)", reg.Name, reg.Src)
	}

	// Do not read these registries recursively, because we already know
	// exactly which repositories to read (getRegistriesToRead()).
	if err := sc.ReadRegistriesGGCR(regs, false); err != nil {
		return fmt.Errorf("reading registries: %w", err)
	}
	if err != nil {
		return fmt.Errorf("filtering promotion edges: %w", err)
	}
	if !ok {
		// If any funny business was detected during a comparison of the manifests
		// with the state of the registries, then exit immediately.
		return errors.New("encountered errors during edge filtering")
	}

	// TODO: Let's rethink this option
	if opts.ParseOnly {
		logrus.Info("Manifests parsed, exiting as ParseOnly is set")
		return nil
	}

	// Verify any signatures in staged images
	logrus.Infof("Validating staging signatures")
	signedEdges, err := p.impl.ValidateStagingSignatures(promotionEdges)
	if err != nil {
		return fmt.Errorf("checking signtaures in staging images: %w", err)
	}

	// Check the pull request
	if !opts.Confirm {
		return p.impl.PrecheckAndExit(opts, mfests)
	}

	logrus.Infof("Promoting images")
	if err := sc.Promote(promotionEdges); err != nil {
		return fmt.Errorf("running image promotion: %w", err)
	}

	logrus.Infof("Replicating signatures")
	if err := p.impl.CopySignatures(opts, sc, signedEdges); err != nil {
		return fmt.Errorf("copying existing signatures: %w", err)
	}

	logrus.Infof("Signing images")
	if err := p.impl.SignImages(opts, sc, promotionEdges); err != nil {
		return fmt.Errorf("signing images: %w", err)
	}

	logrus.Infof("Finish")
	return nil
}

// Snapshot runs the steps to output a representation in json or yaml of a registry
func (p *Promoter) Snapshot(opts *options.Options) (err error) {
	if err := p.impl.ValidateOptions(opts); err != nil {
		return fmt.Errorf("validating options: %w", err)
	}

	if err := p.impl.ActivateServiceAccounts(opts); err != nil {
		return fmt.Errorf("activating service accounts: %w", err)
	}

	p.impl.PrintVersion()
	p.impl.PrintSection("START (SNAPSHOT)", opts.Confirm)

	mfests, err := p.impl.GetSnapshotManifests(opts)
	if err != nil {
		return fmt.Errorf("getting snapshot manifests: %w", err)
	}

	mfests, err = p.impl.AppendManifestToSnapshot(opts, mfests)
	if err != nil {
		return fmt.Errorf("adding the specified manifest to the snapshot context: %w", err)
	}

	rii, err := p.impl.GetRegistryImageInventory(opts, mfests)
	if err != nil {
		return fmt.Errorf("getting registry image inventory: %w", err)
	}

	if err := p.impl.Snapshot(opts, rii); err != nil {
		return fmt.Errorf("generating snapshot: %w", err)
	}
	return nil
}

// CheckManifestLists is a mode that just checks manifests
// and exists.
func (p *Promoter) CheckManifestLists(opts *options.Options) error {
	if err := p.impl.ValidateOptions(opts); err != nil {
		return fmt.Errorf("validating options: %w", err)
	}

	if err := p.impl.ActivateServiceAccounts(opts); err != nil {
		return fmt.Errorf("activating service accounts: %w", err)
	}

	if err := p.impl.ValidateManifestLists(opts); err != nil {
		return fmt.Errorf("checking manifest lists: %w", err)
	}
	return nil
}

// CheckSignatures checks the consistency of a set of images
func (p *Promoter) CheckSignatures(opts *options.Options) error {
	logrus.Info("Fetching latest promoted images")
	images, err := p.impl.GetLatestImages(opts)
	if err != nil {
		return fmt.Errorf("getting latest promoted images: %w", err)
	}

	logrus.Info("Checking signatures")
	results, err := p.impl.GetSignatureStatus(opts, images)
	if err != nil {
		return fmt.Errorf("checking signature status in images: %w", err)
	}

	if results.TotalPartial() == 0 && results.TotalUnsigned() == 0 {
		logrus.Info("Signature consistency OK!")
		return nil
	}

	logrus.Infof("Fixing %d unsigned images", results.TotalUnsigned())
	if err := p.impl.FixMissingSignatures(opts, results); err != nil {
		return fmt.Errorf("fixing missing signatures: %w", err)
	}

	logrus.Infof("Fixing %d images with partial signatures", results.TotalPartial())
	if err := p.impl.FixPartialSignatures(opts, results); err != nil {
		return fmt.Errorf("fixing partial signatures: %w", err)
	}

	return nil
}
