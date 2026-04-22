package parsers

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"pentagi/pkg/ingestion/schema"
)

type TwistlockParser struct{}

// Compile-time assertion that *TwistlockParser satisfies the Parser interface.
var _ Parser = (*TwistlockParser)(nil)

func (p *TwistlockParser) Source() schema.ScanSourceType { return schema.SourceTwistlock }

type twistlockDoc struct {
	Results []twistlockResult `json:"results"`
}

type twistlockResult struct {
	ID               string                `json:"id"`
	Name             string                `json:"name"`
	Tag              string                `json:"tag"`
	Distro           string                `json:"distro"`
	Vulnerabilities  []twistlockVuln       `json:"vulnerabilities"`
	ComplianceIssues []twistlockCompliance `json:"complianceIssues"`
}

type twistlockVuln struct {
	ID             string  `json:"id"`
	PackageName    string  `json:"packageName"`
	PackageVersion string  `json:"packageVersion"`
	Severity       string  `json:"severity"`
	CVSS           float64 `json:"cvss"`
	Description    string  `json:"description"`
}

type twistlockCompliance struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
}

// Parse reads an entire Twistlock JSON document into memory. Twistlock
// exports tend to be on the order of a few MB per scanned image; even
// engagements with hundreds of images produce <100MB of JSON in a single
// dump. If a future engagement pushes that envelope, switch to a streaming
// json.Decoder reading the "results" array element-by-element.
func (p *TwistlockParser) Parse(r io.Reader) (*schema.ReportBundle, error) {
	var doc twistlockDoc
	if err := json.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}

	bundle := &schema.ReportBundle{SourceType: schema.SourceTwistlock}
	for _, res := range doc.Results {
		reg, image := splitImage(res.Name)
		ct := schema.Container{
			Image:    image,
			Tag:      res.Tag,
			Digest:   res.ID,
			Registry: reg,
		}
		ref := ct.TargetRef()
		bundle.Containers = append(bundle.Containers, ct)

		for _, v := range res.Vulnerabilities {
			cvss := v.CVSS
			bundle.Findings = append(bundle.Findings, schema.Finding{
				Type:       schema.TypeContainerCVE,
				Target:     schema.TargetRef{Kind: schema.TargetContainer, Ref: ref},
				Title:      fmt.Sprintf("%s in %s %s", v.ID, v.PackageName, v.PackageVersion),
				CVE:        v.ID,
				CVSSScore:  &cvss,
				Severity:   schema.ParseSeverity(v.Severity),
				Confidence: schema.ConfidenceFirm, // Twistlock matches package versions to NVD; not a live probe
				SourceID:   v.ID,
				Evidence:   mustJSON(v),
			})
		}
		for _, comp := range res.ComplianceIssues {
			bundle.Findings = append(bundle.Findings, schema.Finding{
				Type:       schema.TypeContainerCompliance,
				Target:     schema.TargetRef{Kind: schema.TargetContainer, Ref: ref},
				Title:      comp.Description,
				Severity:   schema.ParseSeverity(comp.Severity),
				Confidence: schema.ConfidenceFirm,
				SourceID:   comp.ID,
				Evidence:   mustJSON(comp),
			})
		}
	}
	bundle.RawEvidence = mustJSON(doc)
	return bundle, nil
}

// splitImage separates "registry.example.com/path/to/image" into its registry
// and image-path components by splitting on the first "/". A bare image with
// no registry prefix returns ("", "image").
func splitImage(full string) (registry, image string) {
	if i := strings.IndexByte(full, '/'); i >= 0 {
		return full[:i], full[i+1:]
	}
	return "", full
}
