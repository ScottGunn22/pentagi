package parsers

import (
	"encoding/xml"
	"io"
	"strconv"
	"strings"

	"pentagi/pkg/ingestion/schema"
)

type NmapParser struct{}

// Compile-time assertion that *NmapParser satisfies the Parser interface.
// Replicate this pattern in every new parser file.
var _ Parser = (*NmapParser)(nil)

func (p *NmapParser) Source() schema.ScanSourceType { return schema.SourceNmap }

type nmapRun struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddr    `xml:"address"`
	Hostnames nmapHostnames `xml:"hostnames"`
	Ports     nmapPorts     `xml:"ports"`
	OS        *nmapOS       `xml:"os"`
}

type nmapAddr struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
}

type nmapHostnames struct {
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostname"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	Protocol string `xml:"protocol,attr"`
	PortID   int    `xml:"portid,attr"`
	State    struct {
		State string `xml:"state,attr"`
	} `xml:"state"`
	Service nmapService `xml:"service"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	Method  string `xml:"method,attr"` // "probed" => high confidence; "table" => guess from port number
}

type nmapOS struct {
	Matches []struct {
		Name     string `xml:"name,attr"`
		Accuracy string `xml:"accuracy,attr"`
		Class    []struct {
			OSFamily string `xml:"osfamily,attr"`
			OSGen    string `xml:"osgen,attr"`
		} `xml:"osclass"`
	} `xml:"osmatch"`
}

// Parse reads an entire nmap XML document into memory. Acceptable because
// nmap reports are bounded in size (tens of MB at most).
//
// Do NOT copy this approach to the Qualys parser — Qualys exports can be
// hundreds of MB and Phase 10 mandates token-streaming via xml.Decoder.Token().
func (p *NmapParser) Parse(r io.Reader) (*schema.ReportBundle, error) {
	var run nmapRun
	if err := xml.NewDecoder(r).Decode(&run); err != nil {
		return nil, err
	}

	bundle := &schema.ReportBundle{SourceType: schema.SourceNmap}

	for _, h := range run.Hosts {
		ip := ""
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				ip = a.Addr
				break
			}
		}
		if ip == "" {
			// TODO(phase-16): emit ingestion.parsers.nmap.host_skipped{reason="no_addr"}
			continue
		}

		hh := schema.Host{IP: ip}
		for _, n := range h.Hostnames.Hostnames {
			hh.Hostnames = append(hh.Hostnames, n.Name)
		}
		if h.OS != nil && len(h.OS.Matches) > 0 {
			m := h.OS.Matches[0]
			acc, _ := strconv.Atoi(m.Accuracy)
			os := &schema.OSFingerprint{Name: m.Name, Accuracy: acc}
			if len(m.Class) > 0 {
				os.Family = m.Class[0].OSFamily
				os.Version = m.Class[0].OSGen
			}
			hh.OS = os
		}

		for _, port := range h.Ports.Ports {
			if port.State.State != "open" {
				continue
			}
			svc := schema.Service{
				Port:     port.PortID,
				Protocol: port.Protocol,
				Name:     port.Service.Name,
				Product:  port.Service.Product,
				Version:  port.Service.Version,
			}
			hh.Services = append(hh.Services, svc)

			bundle.Findings = append(bundle.Findings, schema.Finding{
				Type:       schema.TypeExposedService,
				Target:     schema.TargetRef{Kind: schema.TargetHost, Ref: hh.TargetRef(port.PortID, port.Protocol)},
				Title:      buildExposedServiceTitle(port.Service),
				Severity:   schema.SeverityInfo, // v1: uniform info; severity heuristics deferred to Phase 16
				Confidence: nmapConfidence(port.Service.Method),
				Evidence:   mustJSON(port),
			})
		}
		bundle.Hosts = append(bundle.Hosts, hh)
	}

	bundle.RawEvidence = mustJSON(run)
	return bundle, nil
}

// buildExposedServiceTitle joins non-empty service fields so titles like
// "Exposed service dns" or "Exposed service https nginx 1.24.0" do not
// carry trailing whitespace from missing product/version. Title text is
// fed to LLM embeddings; trailing whitespace pollutes similarity scores.
func buildExposedServiceTitle(s nmapService) string {
	parts := []string{"Exposed service", s.Name}
	if s.Product != "" {
		parts = append(parts, s.Product)
	}
	if s.Version != "" {
		parts = append(parts, s.Version)
	}
	return strings.Join(parts, " ")
}

// nmapConfidence maps the nmap service.method attribute to our normalized
// Confidence enum: "probed" means nmap actually banner-grabbed the
// service (high confidence), "table" means it guessed from the port
// number alone (low confidence), and anything else is treated as a
// medium-strength inference.
func nmapConfidence(method string) schema.Confidence {
	switch method {
	case "probed":
		return schema.ConfidenceCertain
	case "table":
		return schema.ConfidenceTentative
	default:
		return schema.ConfidenceFirm
	}
}
