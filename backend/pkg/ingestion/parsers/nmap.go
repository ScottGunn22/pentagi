package parsers

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"strconv"

	"pentagi/pkg/ingestion/schema"
)

type NmapParser struct{}

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

func (p *NmapParser) Parse(r io.Reader) (*schema.ReportBundle, error) {
	var run nmapRun
	if err := xml.NewDecoder(r).Decode(&run); err != nil {
		return nil, fmt.Errorf("nmap decode: %w", err)
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

			evidence, _ := json.Marshal(port)
			bundle.Findings = append(bundle.Findings, schema.Finding{
				Type:       schema.TypeExposedService,
				Target:     schema.TargetRef{Kind: schema.TargetHost, Ref: hh.TargetRef(port.PortID, port.Protocol)},
				Title:      fmt.Sprintf("Exposed service %s %s %s", port.Service.Name, port.Service.Product, port.Service.Version),
				Severity:   schema.SeverityInfo,
				Confidence: schema.ConfidenceCertain,
				Evidence:   evidence,
			})
		}
		bundle.Hosts = append(bundle.Hosts, hh)
	}

	raw, _ := json.Marshal(run)
	bundle.RawEvidence = raw
	return bundle, nil
}
