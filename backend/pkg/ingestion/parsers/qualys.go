package parsers

import (
	"encoding/xml"
	"fmt"
	"io"
	"strconv"
	"strings"

	"pentagi/pkg/ingestion/schema"
)

type QualysParser struct{}

// Compile-time assertion that *QualysParser satisfies the Parser interface.
var _ Parser = (*QualysParser)(nil)

func (p *QualysParser) Source() schema.ScanSourceType { return schema.SourceQualys }

type qualysVuln struct {
	XMLName  xml.Name `xml:"VULN_INFO"`
	QID      string   `xml:"QID"`
	Title    string   `xml:"TITLE"`
	Severity string   `xml:"SEVERITY"`
	CVSSBase string   `xml:"CVSS_BASE"`
	Result   string   `xml:"RESULT"`
	CVEList  struct {
		IDs []struct {
			ID string `xml:"ID"`
		} `xml:"CVE_ID"`
	} `xml:"CVE_ID_LIST"`
}

// Parse streams a Qualys VM XML document. Streaming via xml.Decoder.Token()
// (not Decoder.Decode) is mandatory: real-world Qualys exports can be in the
// hundreds of MB and would OOM with a single Unmarshal. As a side effect we
// can recover from malformed tails: if the decoder errors mid-document we
// return the bundle assembled so far together with an ErrPartial-wrapped
// error so the controller can mark parse_status='partial' instead of 'failed'.
func (p *QualysParser) Parse(r io.Reader) (*schema.ReportBundle, error) {
	bundle := &schema.ReportBundle{SourceType: schema.SourceQualys}
	dec := xml.NewDecoder(r)
	hosts := map[string]*schema.Host{}
	var currentIP string
	var partial bool

	for {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			partial = true
			break
		}

		start, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}

		switch start.Name.Local {
		case "IP":
			currentIP = ""
			for _, a := range start.Attr {
				if a.Name.Local == "value" {
					currentIP = a.Value
				}
			}
			if currentIP == "" {
				continue
			}
			if _, ok := hosts[currentIP]; !ok {
				hosts[currentIP] = &schema.Host{IP: currentIP}
				for _, a := range start.Attr {
					if a.Name.Local == "name" && a.Value != "" {
						hosts[currentIP].Hostnames = append(hosts[currentIP].Hostnames, a.Value)
					}
				}
			}

		case "VULN_INFO":
			if currentIP == "" {
				// VULN_INFO outside an IP context is malformed; skip but flag partial.
				partial = true
				continue
			}
			var v qualysVuln
			if err := dec.DecodeElement(&v, &start); err != nil {
				partial = true
				break
			}
			finding := schema.Finding{
				Type:       schema.TypeVulnerability,
				Target:     schema.TargetRef{Kind: schema.TargetHost, Ref: "ip:" + currentIP},
				Title:      strings.TrimSpace(v.Title),
				Severity:   mapQualysSeverity(v.Severity),
				Confidence: schema.ConfidenceFirm,
				SourceID:   v.QID,
				Evidence:   mustJSON(v),
			}
			if cvss, err := strconv.ParseFloat(v.CVSSBase, 64); err == nil {
				finding.CVSSScore = &cvss
			}
			if len(v.CVEList.IDs) > 0 {
				finding.CVE = v.CVEList.IDs[0].ID
			}
			bundle.Findings = append(bundle.Findings, finding)
		}
	}

	for _, h := range hosts {
		bundle.Hosts = append(bundle.Hosts, *h)
	}
	if partial {
		return bundle, fmt.Errorf("qualys parse: %w", ErrPartial)
	}
	return bundle, nil
}

// mapQualysSeverity converts Qualys's 1-5 numeric severity (5 = highest) to
// our normalized Severity enum. Anything unrecognized falls back to Info —
// matches the "fail-soft on unknown input" pattern used elsewhere by parsers.
func mapQualysSeverity(s string) schema.Severity {
	switch strings.TrimSpace(s) {
	case "5":
		return schema.SeverityCritical
	case "4":
		return schema.SeverityHigh
	case "3":
		return schema.SeverityMedium
	case "2":
		return schema.SeverityLow
	default:
		return schema.SeverityInfo
	}
}
