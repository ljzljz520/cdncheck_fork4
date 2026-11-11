package cdncheck

import (
	"fmt"
	"sort"
	"strings"
)

// IdentityEntry is a single entry of the unified identity directory.
//
// The directory is the single source of truth shared by the provider
// configuration (provider.yaml), the compiled dataset (sources_data.json)
// and the runtime client. Every legacy provider name, domain suffix and
// wappalyzer technology is resolved through the same entries.
type IdentityEntry struct {
	// ID is the stable, immutable product identifier, e.g. amazon-cloudfront.
	ID string `yaml:"id" json:"id"`
	// Vendor is the vendor/company owning the product, e.g. amazon.
	Vendor string `yaml:"vendor" json:"vendor"`
	// Product is the concrete product. It may be empty when only the vendor
	// can be determined for a detection.
	Product string `yaml:"product,omitempty" json:"product,omitempty"`
	// Aliases lists every legacy/source name that resolves to this entry
	// (CIDR map keys, common suffix source keys, wappalyzer outputs).
	Aliases []string `yaml:"aliases,omitempty" json:"aliases,omitempty"`
	// Categories scopes the aliases to the given detection categories
	// (cdn, waf, cloud). An alias shared by several products, for example
	// "google", must declare a category per product. Aliases without
	// categories are registered globally and act as fallback.
	Categories []string `yaml:"categories,omitempty" json:"categories,omitempty"`
}

// IdentityDirectory is the serialized form of the identity directory.
type IdentityDirectory struct {
	// Entries lists the known vendor/product identities.
	Entries []IdentityEntry `yaml:"entries" json:"entries"`
	// Suffixes maps a concrete domain suffix to an entry ID. It is required
	// when one source key mixes several products, for example the legacy
	// "amazon" source which contains both cloudfront.net and amazonaws.com.
	Suffixes map[string]string `yaml:"suffixes,omitempty" json:"suffixes,omitempty"`
	// Technologies maps a normalized wappalyzer technology to an entry ID.
	// It disambiguates technologies whose legacy output name collapses
	// several products (e.g. "cloudfront" -> amazon-cloudfront).
	Technologies map[string]string `yaml:"technologies,omitempty" json:"technologies,omitempty"`
}

// Identity is a resolved, stable product identity attached to a Result.
type Identity struct {
	// ID is the stable product identifier.
	ID string `json:"id"`
	// Vendor is the vendor/company name.
	Vendor string `json:"vendor"`
	// Product is the concrete product name.
	Product string `json:"product,omitempty"`
}

// Result is an identification result enriched with the stable identity.
//
// Name and Type keep the exact legacy values returned by the classic
// Check* methods so existing callers are fully backward compatible.
type Result struct {
	// Name is the legacy provider name (e.g. "amazon", "cloudfront").
	Name string `json:"name"`
	// Type is the legacy detection category: cdn, waf or cloud.
	Type string `json:"type"`
	// Identity is the stable product identity, nil when it cannot be resolved.
	Identity *Identity `json:"identity,omitempty"`
}

// scopedKey builds the lookup key for a category scoped alias.
func scopedKey(name, itemType string) string {
	return name + "@" + itemType
}

// identityResolver resolves legacy names, suffixes and technologies to the
// stable identity directory.
type identityResolver struct {
	entries      map[string]*Identity
	byKey        map[string]*Identity
	suffixes     map[string]string
	technologies map[string]string
}

// newIdentityResolver builds a resolver from a directory and validates it.
func newIdentityResolver(directory *IdentityDirectory) (*identityResolver, error) {
	resolver := &identityResolver{
		entries:      make(map[string]*Identity),
		byKey:        make(map[string]*Identity),
		suffixes:     make(map[string]string),
		technologies: make(map[string]string),
	}
	if directory == nil {
		return resolver, nil
	}
	for i := range directory.Entries {
		entry := directory.Entries[i]
		if entry.ID == "" {
			return nil, fmt.Errorf("identity directory contains an entry without id")
		}
		if _, exists := resolver.entries[entry.ID]; exists {
			return nil, fmt.Errorf("identity directory contains duplicate entry id %q", entry.ID)
		}
		identity := &Identity{ID: entry.ID, Vendor: entry.Vendor, Product: entry.Product}
		resolver.entries[entry.ID] = identity
		if err := resolver.register(entry.ID, identity, nil); err != nil {
			return nil, err
		}
		for _, alias := range entry.Aliases {
			if err := resolver.register(alias, identity, entry.Categories); err != nil {
				return nil, err
			}
		}
	}
	// Scoped aliases also register a global fallback when the name is not
	// claimed globally, so detections without a usable category (e.g. suffix
	// sources) still resolve. Category scoped keys always take precedence.
	for i := range directory.Entries {
		entry := directory.Entries[i]
		if len(entry.Categories) == 0 {
			continue
		}
		identity := resolver.entries[entry.ID]
		for _, alias := range entry.Aliases {
			if _, ok := resolver.byKey[alias]; !ok {
				resolver.byKey[alias] = identity
			}
		}
	}
	for suffix, id := range directory.Suffixes {
		if _, ok := resolver.entries[id]; !ok {
			return nil, fmt.Errorf("suffix %q references unknown identity id %q", suffix, id)
		}
		resolver.suffixes[strings.ToLower(suffix)] = id
	}
	for technology, id := range directory.Technologies {
		if _, ok := resolver.entries[id]; !ok {
			return nil, fmt.Errorf("technology %q references unknown identity id %q", technology, id)
		}
		resolver.technologies[strings.ToLower(technology)] = id
	}
	return resolver, nil
}

// register binds a name to an identity, optionally scoped to categories.
// The first registration wins so conflicting aliases fail fast instead of
// silently returning the wrong product.
func (r *identityResolver) register(name string, identity *Identity, categories []string) error {
	if len(categories) == 0 {
		key := name
		if existing, ok := r.byKey[key]; ok && existing.ID != identity.ID {
			return fmt.Errorf("alias %q is claimed by both %q and %q", name, existing.ID, identity.ID)
		}
		r.byKey[key] = identity
		return nil
	}
	for _, itemType := range categories {
		key := scopedKey(name, itemType)
		if existing, ok := r.byKey[key]; ok && existing.ID != identity.ID {
			return fmt.Errorf("alias %q (category %s) is claimed by both %q and %q", name, itemType, existing.ID, identity.ID)
		}
		r.byKey[key] = identity
	}
	return nil
}

// resolve maps a legacy provider name to an identity. Category scoped
// aliases are preferred, global aliases are used as fallback.
func (r *identityResolver) resolve(name, itemType string) *Identity {
	if name == "" {
		return nil
	}
	if itemType != "" {
		if identity, ok := r.byKey[scopedKey(name, itemType)]; ok {
			return identity
		}
	}
	return r.byKey[name]
}

// resolveSuffix maps a matched domain suffix to an identity, falling back
// to the legacy source name when no explicit suffix mapping exists.
func (r *identityResolver) resolveSuffix(suffix, source string) *Identity {
	if id, ok := r.suffixes[strings.ToLower(suffix)]; ok {
		return r.entries[id]
	}
	return r.resolve(source, "waf")
}

// resolveTechnology maps a normalized wappalyzer technology to an identity,
// falling back to the legacy provider name it used to return.
func (r *identityResolver) resolveTechnology(technology, legacyName string) *Identity {
	if id, ok := r.technologies[strings.ToLower(technology)]; ok {
		return r.entries[id]
	}
	return r.resolve(legacyName, "")
}

// lookup resolves an identity ID or a global alias (used by matchers/filters).
func (r *identityResolver) lookup(token string) (*Identity, bool) {
	if identity, ok := r.entries[token]; ok {
		return identity, true
	}
	if identity, ok := r.byKey[token]; ok {
		return identity, true
	}
	return nil, false
}

// identities returns all directory identities sorted by stable ID.
func (r *identityResolver) identities() []Identity {
	out := make([]Identity, 0, len(r.entries))
	for _, identity := range r.entries {
		out = append(out, *identity)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// MergeIdentityDirectories merges override into base. Entries with the same
// ID are replaced, new entries are appended and suffix/technology mappings
// of override take precedence. A nil override returns a copy of base.
func MergeIdentityDirectories(base, override *IdentityDirectory) *IdentityDirectory {
	merged := &IdentityDirectory{
		Entries:      append([]IdentityEntry(nil), base.Entries...),
		Suffixes:     make(map[string]string, len(base.Suffixes)),
		Technologies: make(map[string]string, len(base.Technologies)),
	}
	for suffix, id := range base.Suffixes {
		merged.Suffixes[suffix] = id
	}
	for technology, id := range base.Technologies {
		merged.Technologies[technology] = id
	}
	if override == nil {
		return merged
	}
	index := make(map[string]int, len(merged.Entries))
	for i, entry := range merged.Entries {
		index[entry.ID] = i
	}
	for _, entry := range override.Entries {
		if i, ok := index[entry.ID]; ok {
			merged.Entries[i] = entry
		} else {
			merged.Entries = append(merged.Entries, entry)
		}
	}
	for suffix, id := range override.Suffixes {
		merged.Suffixes[suffix] = id
	}
	for technology, id := range override.Technologies {
		merged.Technologies[technology] = id
	}
	return merged
}

// ValidateIdentityDirectory validates a serialized directory and returns an
// error when entries, aliases or suffix/technology mappings are inconsistent.
func ValidateIdentityDirectory(directory *IdentityDirectory) error {
	_, err := newIdentityResolver(directory)
	return err
}

// DefaultIdentityDirectory returns the built-in identity directory. It is
// the canonical directory embedded into the compiled dataset and used when
// the dataset does not carry one.
func DefaultIdentityDirectory() *IdentityDirectory {
	return &IdentityDirectory{
		Entries: []IdentityEntry{
			// Amazon: the generic amazon/aws vendor identity must stay
			// distinct from the concrete CloudFront product.
			{ID: "amazon-cloudfront", Vendor: "amazon", Product: "cloudfront", Aliases: []string{"cloudfront"}, Categories: []string{"cdn"}},
			{ID: "amazon-aws", Vendor: "amazon", Product: "aws", Aliases: []string{"amazon", "aws"}},

			// Google: the same legacy "google" name denotes two products
			// depending on the detection category.
			{ID: "google-cloud-cdn", Vendor: "google", Product: "cloud-cdn", Aliases: []string{"google"}, Categories: []string{"cdn"}},
			{ID: "google-cloud", Vendor: "google", Product: "cloud-platform", Aliases: []string{"google"}, Categories: []string{"cloud"}},

			{ID: "cloudflare", Vendor: "cloudflare", Product: "cloudflare", Aliases: []string{"cloudflare"}},

			// Imperva Incapsula: "imperva" and "incapsula" are explicit
			// aliases of the same product; legacy names are preserved.
			{ID: "imperva-incapsula", Vendor: "imperva", Product: "incapsula", Aliases: []string{"incapsula", "imperva"}},

			// F5: Distributed Cloud (incl. the former Volterra) and BIG-IP
			// are distinct products sharing the legacy "f5" output name.
			{ID: "f5-distributed-cloud", Vendor: "f5", Product: "distributed-cloud", Aliases: []string{"f5"}},
			{ID: "f5-bigip", Vendor: "f5", Product: "big-ip"},

			{ID: "akamai", Vendor: "akamai", Product: "akamai", Aliases: []string{"akamai"}},
			{ID: "fastly", Vendor: "fastly", Product: "fastly", Aliases: []string{"fastly"}},

			{ID: "microsoft-azure", Vendor: "microsoft", Product: "azure", Aliases: []string{"azure"}},
			{ID: "microsoft-office365", Vendor: "microsoft", Product: "office365", Aliases: []string{"office365"}},

			// Huawei: CDN edges and the WAF product are distinct entries.
			{ID: "huawei-cdn", Vendor: "huawei", Product: "cdn", Aliases: []string{"huawei"}, Categories: []string{"cdn"}},
			{ID: "huawei-waf", Vendor: "huawei", Product: "waf", Aliases: []string{"huawei-waf"}},

			// Qihoo 360 / Qianxin: the three legacy 360 CDN source names
			// are explicit aliases of one CDN product.
			{ID: "qihoo360-cdn", Vendor: "qihoo360", Product: "cdn", Aliases: []string{"360-cdn", "qianxin-360-cdn", "qihoo-360-cdn"}},
			{ID: "qianxin-waf", Vendor: "qianxin", Product: "waf", Aliases: []string{"qianxin"}},
			{ID: "qianxin-legendsec-waf", Vendor: "qianxin", Product: "legendsec-waf", Aliases: []string{"legendsec"}},

			{ID: "alibaba-aliyun", Vendor: "alibaba", Product: "aliyun", Aliases: []string{"aliyun"}},
			{ID: "tencent-cdn", Vendor: "tencent", Product: "cdn", Aliases: []string{"tencent"}},
			{ID: "baidu-cdn", Vendor: "baidu", Product: "cdn", Aliases: []string{"baidu"}},
			{ID: "wangsu-cdn", Vendor: "wangsu", Product: "cdn", Aliases: []string{"wangsu"}},
			{ID: "yundun", Vendor: "yundun", Product: "yundun", Aliases: []string{"yundun"}},
			{ID: "jiasule", Vendor: "jiasule", Product: "jiasule", Aliases: []string{"jiasule"}},
			{ID: "arvancloud", Vendor: "arvancloud", Product: "arvancloud", Aliases: []string{"arvancloud"}},
			{ID: "qrator", Vendor: "qrator", Product: "qrator", Aliases: []string{"qrator"}},
			{ID: "edgecast", Vendor: "edgecast", Product: "edgecast", Aliases: []string{"edgecast"}},
			{ID: "qiniu", Vendor: "qiniu", Product: "qiniu", Aliases: []string{"qiniu"}},
			{ID: "upyun", Vendor: "upyun", Product: "upyun", Aliases: []string{"upyun"}},
			{ID: "jdcloud", Vendor: "jdcloud", Product: "jdcloud", Aliases: []string{"jdcloud"}},
			{ID: "baishan", Vendor: "baishan", Product: "baishan", Aliases: []string{"baishan"}},
			{ID: "dnion", Vendor: "dnion", Product: "dnion", Aliases: []string{"dnion"}},
			{ID: "wangdi", Vendor: "wangdi", Product: "wangdi", Aliases: []string{"wangdi"}},
			{ID: "cndns", Vendor: "cndns", Product: "cndns", Aliases: []string{"cndns"}},
			{ID: "dbappsecurity", Vendor: "dbappsecurity", Product: "dbappsecurity", Aliases: []string{"dbappsecurity"}},
			{ID: "sangfor", Vendor: "sangfor", Product: "sangfor", Aliases: []string{"sangfor"}},
			{ID: "nsfocus", Vendor: "nsfocus", Product: "nsfocus", Aliases: []string{"nsfocus"}},
			{ID: "bluedon", Vendor: "bluedon", Product: "bluedon", Aliases: []string{"bluedon"}},
			{ID: "15cdn", Vendor: "15cdn", Product: "15cdn", Aliases: []string{"15cdn"}},
			{ID: "cafe24", Vendor: "cafe24", Product: "cafe24", Aliases: []string{"cafe24"}},
			{ID: "cdnetworks", Vendor: "cdnetworks", Product: "cdnetworks", Aliases: []string{"cdnetworks"}},
			{ID: "gcore", Vendor: "gcore", Product: "gcore", Aliases: []string{"gcore"}},
			{ID: "gocache", Vendor: "gocache", Product: "gocache", Aliases: []string{"gocache"}},
			{ID: "kinx", Vendor: "kinx", Product: "kinx", Aliases: []string{"kinx"}},
			{ID: "lgtelecom", Vendor: "lgtelecom", Product: "lgtelecom", Aliases: []string{"lgtelecom"}},
			{ID: "skbroadband", Vendor: "skbroadband", Product: "skbroadband", Aliases: []string{"skbroadband"}},
			{ID: "gabia", Vendor: "gabia", Product: "gabia", Aliases: []string{"gabia"}},
			{ID: "hostway", Vendor: "hostway", Product: "hostway", Aliases: []string{"hostway"}},
			{ID: "ktcloud", Vendor: "ktcloud", Product: "ktcloud", Aliases: []string{"ktcloud"}},
			{ID: "navercloud", Vendor: "navercloud", Product: "navercloud", Aliases: []string{"navercloud"}},
			{ID: "nhncloud", Vendor: "nhncloud", Product: "nhncloud", Aliases: []string{"nhncloud"}},
			{ID: "oracle-cloud", Vendor: "oracle", Product: "cloud", Aliases: []string{"oracle"}},
			{ID: "zscaler", Vendor: "zscaler", Product: "zscaler", Aliases: []string{"zscaler"}},

			// Wappalyzer-only technologies.
			{ID: "sucuri", Vendor: "sucuri", Product: "sucuri", Aliases: []string{"sucuri"}},
			{ID: "reblaze", Vendor: "reblaze", Product: "reblaze", Aliases: []string{"reblaze"}},
			{ID: "stackpath", Vendor: "stackpath", Product: "stackpath", Aliases: []string{"stackpath"}},
			{ID: "bunny-cdn", Vendor: "bunny", Product: "cdn", Aliases: []string{"bunny", "bunnycdn"}},
			{ID: "cdn77", Vendor: "cdn77", Product: "cdn77", Aliases: []string{"cdn77"}},
			{ID: "keycdn", Vendor: "keycdn", Product: "keycdn", Aliases: []string{"keycdn"}},
			{ID: "vercel", Vendor: "vercel", Product: "vercel", Aliases: []string{"vercel"}},
			{ID: "netlify", Vendor: "netlify", Product: "netlify", Aliases: []string{"netlify"}},
			{ID: "cachefly", Vendor: "cachefly", Product: "cachefly", Aliases: []string{"cachefly"}},
			{ID: "limelight", Vendor: "limelight", Product: "limelight", Aliases: []string{"limelight"}},
			{ID: "ddos-guard", Vendor: "ddos-guard", Product: "ddos-guard", Aliases: []string{"ddos-guard"}},
			{ID: "section-io", Vendor: "section.io", Product: "section.io", Aliases: []string{"section.io"}},
		},
		Suffixes: map[string]string{
			// The legacy "amazon" source mixes CloudFront edges with generic
			// AWS infrastructure; generic amazonaws.com names must never be
			// forced into CloudFront.
			"cloudfront.net": "amazon-cloudfront",
			"amazonaws.com":  "amazon-aws",
			// edgesuite.net is shared by the akamai and edgecast sources;
			// the directory pins the ambiguous suffix to Akamai.
			"edgesuite.net": "akamai",
		},
		Technologies: map[string]string{
			// The wappalyzer "cloudfront" technology used to collapse to the
			// generic "amazon" name; pin it to the concrete product.
			"cloudfront": "amazon-cloudfront",
			"azure cdn":  "microsoft-azure",
			// F5 technologies distinguish BIG-IP from Distributed Cloud.
			"f5 big-ip":                              "f5-bigip",
			"f5 big-ip access policy manager":        "f5-bigip",
			"f5 big-ip local traffic manager":        "f5-bigip",
			"f5 big-ip application security manager": "f5-bigip",
			"f5 distributed cloud":                   "f5-distributed-cloud",
		},
	}
}

// defaultIdentityResolver is the resolver backed by the built-in directory.
var defaultIdentityResolver = mustNewIdentityResolver(DefaultIdentityDirectory())

func mustNewIdentityResolver(directory *IdentityDirectory) *identityResolver {
	resolver, err := newIdentityResolver(directory)
	if err != nil {
		panic(fmt.Sprintf("invalid default identity directory: %v", err))
	}
	return resolver
}

// IdentityOf resolves an identity ID or any legacy alias to the stable
// identity. It is intended for user supplied match/filter values.
func (c *Client) IdentityOf(token string) (*Identity, bool) {
	return c.identity.lookup(token)
}

// IdentityFor resolves a legacy provider name within a detection category
// (cdn, waf or cloud) to the stable identity.
func (c *Client) IdentityFor(name, itemType string) (*Identity, bool) {
	identity := c.identity.resolve(name, itemType)
	return identity, identity != nil
}

// Identities returns every identity known to the client directory.
func (c *Client) Identities() []Identity {
	return c.identity.identities()
}

// productIDsFor returns the sorted stable product IDs for a category map.
func productIDsFor(providers map[string][]string, itemType string) []string {
	seen := make(map[string]struct{})
	ids := make([]string, 0)
	for name := range providers {
		if identity := defaultIdentityResolver.resolve(name, itemType); identity != nil {
			if _, ok := seen[identity.ID]; !ok {
				seen[identity.ID] = struct{}{}
				ids = append(ids, identity.ID)
			}
		}
	}
	sort.Strings(ids)
	return ids
}

// DefaultCDNProductIDs returns the stable CDN product IDs backing the
// compiled dataset.
func DefaultCDNProductIDs() []string {
	return productIDsFor(generatedData.CDN, "cdn")
}

// DefaultWAFProductIDs returns the stable WAF product IDs backing the
// compiled dataset.
func DefaultWAFProductIDs() []string {
	return productIDsFor(generatedData.WAF, "waf")
}

// DefaultCloudProductIDs returns the stable cloud product IDs backing the
// compiled dataset.
func DefaultCloudProductIDs() []string {
	return productIDsFor(generatedData.Cloud, "cloud")
}
