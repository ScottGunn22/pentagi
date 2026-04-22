package parsers

import (
	"encoding/xml"
	"io"
	"strings"

	"pentagi/pkg/ingestion/schema"
)

type BurpParser struct{}

// Compile-time assertion that *BurpParser satisfies the Parser interface.
var _ Parser = (*BurpParser)(nil)

func (p *BurpParser) Source() schema.ScanSourceType { return schema.SourceBurp }

type burpIssues struct {
	XMLName xml.Name    `xml:"issues"`
	Issues  []burpIssue `xml:"issue"`
}

type burpIssue struct {
	SerialNumber string `xml:"serialNumber"`
	Name         string `xml:"name"`
	Host         string `xml:"host"`
	Path         string `xml:"path"`
	Location     string `xml:"location"`
	Severity     string `xml:"severity"`
	Confidence   string `xml:"confidence"`
}

// Parse reads an entire Burp XML document into memory. Acceptable because
// Burp project exports for a single scan are bounded in size; very large
// engagements export by site/scope partition rather than as one mega-file.
func (p *BurpParser) Parse(r io.Reader) (*schema.ReportBundle, error) {
	var doc burpIssues
	if err := xml.NewDecoder(r).Decode(&doc); err != nil {
		return nil, err
	}

	bundle := &schema.ReportBundle{SourceType: schema.SourceBurp}
	for _, iss := range doc.Issues {
		f := schema.Finding{
			Type:       schema.TypeWebIssue,
			Target:     schema.TargetRef{Kind: schema.TargetWebEndpoint, Ref: "url:" + iss.Location},
			Title:      iss.Name,
			Severity:   schema.ParseSeverity(iss.Severity),
			Confidence: burpConfidence(iss.Confidence),
			SourceID:   iss.SerialNumber,
			Evidence:   mustJSON(iss),
		}
		bundle.Findings = append(bundle.Findings, f)
		bundle.WebEndpoints = append(bundle.WebEndpoints, schema.WebEndpoint{URL: iss.Location})
	}
	bundle.RawEvidence = mustJSON(doc)
	return bundle, nil
}

// burpConfidence maps Burp's Certain/Firm/Tentative scale into our
// normalized Confidence enum. Anything unknown defaults to Tentative — Burp
// defaulting to higher confidence on garbled input would be misleading.
func burpConfidence(s string) schema.Confidence {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "certain":
		return schema.ConfidenceCertain
	case "firm":
		return schema.ConfidenceFirm
	default:
		return schema.ConfidenceTentative
	}
}
