package schema

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type ScanSourceType string

const (
	SourceQualys    ScanSourceType = "qualys"
	SourceTwistlock ScanSourceType = "twistlock"
	SourceNmap      ScanSourceType = "nmap"
	SourceBurp      ScanSourceType = "burp"
)

type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

func ParseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info", "informational", "information", "0":
		return SeverityInfo
	case "low", "1":
		return SeverityLow
	case "medium", "med", "moderate", "2", "3":
		return SeverityMedium
	case "high", "4":
		return SeverityHigh
	case "critical", "crit", "5":
		return SeverityCritical
	}
	return SeverityInfo
}

type Confidence string

const (
	ConfidenceCertain   Confidence = "certain"
	ConfidenceFirm      Confidence = "firm"
	ConfidenceTentative Confidence = "tentative"
)

type FindingType string

const (
	TypeVulnerability       FindingType = "vulnerability"
	TypeWebIssue            FindingType = "web_issue"
	TypeExposedService      FindingType = "exposed_service"
	TypeContainerCVE        FindingType = "container_cve"
	TypeContainerCompliance FindingType = "container_compliance"
	TypeSecretExposure      FindingType = "secret_exposure"
)

type TargetKind string

const (
	TargetHost        TargetKind = "host"
	TargetWebEndpoint TargetKind = "web_endpoint"
	TargetContainer   TargetKind = "container"
)

type TargetRef struct {
	Kind TargetKind
	Ref  string
}

type ReportBundle struct {
	SourceType   ScanSourceType
	ScanDate     *time.Time
	Hosts        []Host
	Containers   []Container
	WebEndpoints []WebEndpoint
	Findings     []Finding
	RawEvidence  json.RawMessage
}

type OSFingerprint struct {
	Family   string
	Name     string
	Version  string
	Accuracy int // 0-100
}

type Host struct {
	IP        string
	Hostnames []string
	OS        *OSFingerprint
	Services  []Service
}

// TargetRef builds "ip:<ip>:<port>/<proto>" for a host+service combo.
func (h *Host) TargetRef(port int, proto string) string {
	return fmt.Sprintf("ip:%s:%d/%s", h.IP, port, proto)
}

type EvidenceRef struct {
	SourceFile string
	Path       string // xpath, jsonpath, line range, etc
}

type Service struct {
	Port     int
	Protocol string
	Name     string
	Product  string
	Version  string
	Evidence EvidenceRef
}

type LayerInfo struct {
	Digest  string
	Command string
}

type Container struct {
	Image    string
	Tag      string
	Digest   string
	Registry string
	Layers   []LayerInfo
}

func (c *Container) TargetRef() string {
	if c.Digest != "" {
		return fmt.Sprintf("img:%s@%s", c.Image, c.Digest)
	}
	return fmt.Sprintf("img:%s:%s", c.Image, c.Tag)
}

type WebEndpoint struct {
	URL    string
	Method string
	Params []string
}

func (w *WebEndpoint) TargetRef() string {
	if w.Method != "" {
		return fmt.Sprintf("url:%s %s", w.Method, w.URL)
	}
	return "url:" + w.URL
}

type Finding struct {
	Type       FindingType
	Target     TargetRef
	Title      string
	CVE        string
	CVSSScore  *float64
	Severity   Severity
	Confidence Confidence
	SourceID   string
	Evidence   json.RawMessage
}
