package cdncheck

import (
	"strings"

	"github.com/pkg/errors"
	"github.com/weppos/publicsuffix-go/publicsuffix"
)

var suffixToSource map[string]string

// cdnWappalyzerTechnologies contains a map of wappalyzer technologies to cdns
var cdnWappalyzerTechnologies = map[string]string{
	"imperva":    "imperva",
	"incapsula":  "incapsula",
	"cloudflare": "cloudflare",
	"cloudfront": "amazon",
	"akamai":     "akamai",
	"fastly":     "fastly",
	"sucuri":     "sucuri",
	"reblaze":    "reblaze",
	"stackpath":  "stackpath",
	"bunny":      "bunny",
	"bunnycdn":   "bunny",
	"cdn77":      "cdn77",
	"keycdn":     "keycdn",
	"vercel":     "vercel",
	"netlify":    "netlify",
	"azure cdn":  "azure",
	"cachefly":   "cachefly",
	"edgecast":   "edgecast",
	"limelight":  "limelight",
	"ddos-guard": "ddos-guard",
	"arvancloud": "arvancloud",
	"qrator":     "qrator",
	"section.io": "section.io",
	"f5 big-ip":                   "f5",
	"f5 big-ip access policy manager": "f5",
	"f5 big-ip local traffic manager": "f5",
	"f5 big-ip application security manager": "f5",
	"f5 distributed cloud":        "f5",
}

// CheckFQDN checks if fqdns are known cloud ones
func (c *Client) CheckSuffix(fqdns ...string) (isCDN bool, provider string, itemType string, err error) {
	matched, source, _, err := c.matchSuffix(fqdns)
	if err != nil || !matched {
		return matched, source, "", err
	}
	return true, source, "waf", nil
}

// matchSuffix looks up the first known suffix among the fqdns and returns
// both the legacy source name and the concrete suffix that matched.
func (c *Client) matchSuffix(fqdns []string) (matched bool, source string, matchedSuffix string, err error) {
	c.Do(func() {
		suffixToSource = make(map[string]string)
		for src, suffixes := range generatedData.Common {
			for _, suffix := range suffixes {
				suffixToSource[suffix] = src
			}
		}
	})
	for _, fqdn := range fqdns {
		if _, err := publicsuffix.Parse(fqdn); err != nil {
			return false, "", "", errors.Wrap(err, "could not parse fqdn")
		}
		trimmed := strings.ToLower(strings.TrimSuffix(fqdn, "."))
		parts := strings.Split(trimmed, ".")
		for i := 0; i < len(parts); i++ {
			candidate := strings.Join(parts[i:], ".")
			if discovered, ok := suffixToSource[candidate]; ok {
				return true, discovered, candidate, nil
			}
		}
	}
	return false, "", "", nil
}

// CheckSuffixResult is the identity enriched variant of CheckSuffix. The
// concrete matched suffix is used to disambiguate sources that mix several
// products (e.g. cloudfront.net vs amazonaws.com under the legacy "amazon"
// source). The legacy category stays "waf" and Result.Name keeps the legacy
// source name.
func (c *Client) CheckSuffixResult(fqdns ...string) (isCDN bool, result *Result, err error) {
	matched, source, matchedSuffix, err := c.matchSuffix(fqdns)
	if err != nil || !matched {
		return matched, nil, err
	}
	return true, &Result{
		Name:     source,
		Type:     "waf",
		Identity: c.identity.resolveSuffix(matchedSuffix, source),
	}, nil
}

// normalizeTechnology applies the legacy wappalyzer technology normalization.
func normalizeTechnology(technology string) string {
	if strings.Contains(technology, ":") {
		if parts := strings.SplitN(technology, ":", 2); len(parts) == 2 {
			technology = parts[0]
		}
	}
	return strings.ToLower(technology)
}

// CheckWappalyzer checks if the wappalyzer detection are a part of CDN
func (c *Client) CheckWappalyzer(data map[string]struct{}) (isCDN bool, provider string, err error) {
	for technology := range data {
		technology = normalizeTechnology(technology)
		if discovered, ok := cdnWappalyzerTechnologies[technology]; ok {
			return true, discovered, nil
		}
	}
	return false, "", nil
}

// CheckWappalyzerResult is the identity enriched variant of CheckWappalyzer.
// Result.Name keeps the legacy provider value while Identity resolves the
// concrete product (for example the "cloudfront" technology resolves to
// amazon-cloudfront instead of the generic amazon vendor name).
func (c *Client) CheckWappalyzerResult(data map[string]struct{}) (isCDN bool, result *Result, err error) {
	for technology := range data {
		normalized := normalizeTechnology(technology)
		if discovered, ok := cdnWappalyzerTechnologies[normalized]; ok {
			return true, &Result{
				Name:     discovered,
				Identity: c.identity.resolveTechnology(normalized, discovered),
			}, nil
		}
	}
	return false, nil, nil
}
