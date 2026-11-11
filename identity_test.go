package cdncheck

import (
	"net"
	"os"
	"reflect"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestDefaultIdentityDirectoryIsValid(t *testing.T) {
	require.NoError(t, ValidateIdentityDirectory(DefaultIdentityDirectory()))
}

// normalizeDirectory renders a directory into comparable maps so slice
// ordering does not hide drift between yaml, json and the built-in default.
func normalizeDirectory(directory *IdentityDirectory) (map[string]IdentityEntry, map[string]string, map[string]string) {
	entries := make(map[string]IdentityEntry, len(directory.Entries))
	for _, entry := range directory.Entries {
		entries[entry.ID] = entry
	}
	return entries, directory.Suffixes, directory.Technologies
}

func TestCompiledDatasetEmbedsDefaultDirectory(t *testing.T) {
	require.NotNil(t, generatedData.Identity, "compiled sources_data.json must embed the identity directory")
	gotEntries, gotSuffixes, gotTech := normalizeDirectory(generatedData.Identity)
	wantEntries, wantSuffixes, wantTech := normalizeDirectory(DefaultIdentityDirectory())
	require.Equal(t, wantEntries, gotEntries)
	require.Equal(t, wantSuffixes, gotSuffixes)
	require.Equal(t, wantTech, gotTech)
}

func TestProviderConfigEmbedsDefaultDirectory(t *testing.T) {
	raw, err := os.ReadFile("cmd/generate-index/provider.yaml")
	require.NoError(t, err)

	var categories struct {
		Identity *IdentityDirectory `yaml:"identity"`
	}
	require.NoError(t, yaml.Unmarshal(raw, &categories))
	require.NotNil(t, categories.Identity, "provider.yaml must declare the identity directory")

	gotEntries, gotSuffixes, gotTech := normalizeDirectory(categories.Identity)
	wantEntries, wantSuffixes, wantTech := normalizeDirectory(DefaultIdentityDirectory())
	require.Equal(t, wantEntries, gotEntries, "provider.yaml identity entries drift from built-in directory")
	require.Equal(t, wantSuffixes, gotSuffixes)
	require.Equal(t, wantTech, gotTech)
}

// TestEveryLegacyNameResolves ensures names used by the four data sources and
// the wappalyzer map all have a stable identity.
func TestEveryLegacyNameResolves(t *testing.T) {
	client := New()
	for name := range generatedData.CDN {
		identity, ok := client.IdentityFor(name, "cdn")
		require.True(t, ok, "cdn provider %q has no identity", name)
		require.NotEmpty(t, identity.ID)
	}
	for name := range generatedData.WAF {
		identity, ok := client.IdentityFor(name, "waf")
		require.True(t, ok, "waf provider %q has no identity", name)
		require.NotEmpty(t, identity.ID)
	}
	for name := range generatedData.Cloud {
		identity, ok := client.IdentityFor(name, "cloud")
		require.True(t, ok, "cloud provider %q has no identity", name)
		require.NotEmpty(t, identity.ID)
	}
	for name := range generatedData.Common {
		identity, ok := client.IdentityFor(name, "waf")
		require.True(t, ok, "common suffix source %q has no identity", name)
		require.NotEmpty(t, identity.ID)
	}
	for technology, legacy := range cdnWappalyzerTechnologies {
		identity := client.identity.resolveTechnology(technology, legacy)
		require.NotNil(t, identity, "wappalyzer technology %q has no identity", technology)
	}
}

// TestCloudFrontConsistentAcrossMethods verifies that CIDR, suffix and
// technology detection all expose the same stable product id even though the
// legacy names differ ("cloudfront" vs "amazon").
func TestCloudFrontConsistentAcrossMethods(t *testing.T) {
	client := New()

	// 1. CIDR detection (cdn category) returns the legacy "cloudfront" name.
	matched, ipResult, err := client.CheckResult(net.ParseIP("23.228.249.1"))
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "cloudfront", ipResult.Name, "legacy CIDR name must stay unchanged")
	require.Equal(t, "cdn", ipResult.Type)
	require.NotNil(t, ipResult.Identity)
	require.Equal(t, "amazon-cloudfront", ipResult.Identity.ID)
	require.Equal(t, "amazon", ipResult.Identity.Vendor)
	require.Equal(t, "cloudfront", ipResult.Identity.Product)

	// 2. Suffix detection returns the legacy "amazon" name.
	matched, suffixResult, err := client.CheckSuffixResult("test.cloudfront.net")
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "amazon", suffixResult.Name, "legacy suffix name must stay unchanged")
	require.Equal(t, "waf", suffixResult.Type, "suffix category determination must stay waf")
	require.NotNil(t, suffixResult.Identity)
	require.Equal(t, "amazon-cloudfront", suffixResult.Identity.ID)

	// 3. Wappalyzer detection also returns the legacy "amazon" name.
	matched, techResult, err := client.CheckWappalyzerResult(map[string]struct{}{"cloudfront": {}})
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "amazon", techResult.Name, "legacy technology name must stay unchanged")
	require.NotNil(t, techResult.Identity)
	require.Equal(t, "amazon-cloudfront", techResult.Identity.ID)

	require.Equal(t, ipResult.Identity.ID, suffixResult.Identity.ID)
	require.Equal(t, ipResult.Identity.ID, techResult.Identity.ID)
}

// TestGenericAmazonDomainIsNotCloudFront protects against forcing generic AWS
// infrastructure domains into the CloudFront product.
func TestGenericAmazonDomainIsNotCloudFront(t *testing.T) {
	client := New()

	matched, result, err := client.CheckSuffixResult("my-lb-123.us-east-1.elb.amazonaws.com")
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "amazon", result.Name)
	require.NotNil(t, result.Identity)
	require.Equal(t, "amazon-aws", result.Identity.ID)
	require.Equal(t, "amazon", result.Identity.Vendor)
	require.NotEqual(t, "amazon-cloudfront", result.Identity.ID)

	cloudFront, cloudFrontOK := client.IdentityOf("amazon-cloudfront")
	aws, awsOK := client.IdentityOf("amazon-aws")
	require.True(t, cloudFrontOK)
	require.True(t, awsOK)
	require.NotEqual(t, cloudFront.ID, aws.ID)
	require.Equal(t, cloudFront.Vendor, aws.Vendor, "both products share the amazon vendor")
}

// TestGoogleVendorProductSplit keeps the single legacy "google" name but
// splits it into two products by category.
func TestGoogleVendorProductSplit(t *testing.T) {
	client := New()

	matched, cloudResult, err := client.CheckResult(net.ParseIP("34.67.190.20"))
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "google", cloudResult.Name)
	require.Equal(t, "cloud", cloudResult.Type)
	require.Equal(t, "google-cloud", cloudResult.Identity.ID)
	require.Equal(t, "google", cloudResult.Identity.Vendor)

	matched, cdnResult, err := client.CheckResult(net.ParseIP("142.250.80.46"))
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "google", cdnResult.Name)
	require.Equal(t, "cdn", cdnResult.Type)
	require.Equal(t, "google-cloud-cdn", cdnResult.Identity.ID)

	require.NotEqual(t, cloudResult.Identity.ID, cdnResult.Identity.ID)
	require.Equal(t, cloudResult.Identity.Vendor, cdnResult.Identity.Vendor)
}

// TestAmbiguousAliases covers the explicitly documented alias groups.
func TestAmbiguousAliases(t *testing.T) {
	client := New()

	// Imperva / Incapsula: two legacy names and three detection paths, one id.
	imperva, ok := client.IdentityOf("imperva")
	require.True(t, ok)
	incapsula, ok := client.IdentityOf("incapsula")
	require.True(t, ok)
	require.Equal(t, "imperva-incapsula", imperva.ID)
	require.Equal(t, imperva.ID, incapsula.ID)

	matched, techImperva, err := client.CheckWappalyzerResult(map[string]struct{}{"imperva": {}})
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "imperva", techImperva.Name)
	require.Equal(t, "imperva-incapsula", techImperva.Identity.ID)

	matched, techIncapsula, err := client.CheckWappalyzerResult(map[string]struct{}{"incapsula": {}})
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "incapsula", techIncapsula.Name, "legacy name preserved")
	require.Equal(t, "imperva-incapsula", techIncapsula.Identity.ID)

	matched, wafResult, err := client.CheckWAFResult(net.ParseIP("199.83.128.1"))
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "incapsula", wafResult.Name)
	require.Equal(t, "imperva-incapsula", wafResult.Identity.ID)

	matched, suffixResult, err := client.CheckSuffixResult("app.impervadns.net")
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "imperva-incapsula", suffixResult.Identity.ID)

	// Bunny / BunnyCDN technology aliases.
	for _, technology := range []string{"bunny", "bunnycdn"} {
		matched, result, err := client.CheckWappalyzerResult(map[string]struct{}{technology: {}})
		require.NoError(t, err)
		require.True(t, matched)
		require.Equal(t, "bunny", result.Name, "legacy name preserved for %s", technology)
		require.Equal(t, "bunny-cdn", result.Identity.ID)
	}

	// Qihoo 360 CDN source names are explicit aliases of one product.
	for _, alias := range []string{"360-cdn", "qianxin-360-cdn", "qihoo-360-cdn"} {
		identity, ok := client.IdentityOf(alias)
		require.True(t, ok)
		require.Equal(t, "qihoo360-cdn", identity.ID, "alias %s", alias)
	}

	// Huawei CDN vs Huawei WAF share the vendor but are distinct products.
	huaweiCDN, ok := client.IdentityFor("huawei", "cdn")
	require.True(t, ok)
	huaweiWAF, ok := client.IdentityOf("huawei-waf")
	require.True(t, ok)
	require.NotEqual(t, huaweiCDN.ID, huaweiWAF.ID)
	require.Equal(t, "huawei", huaweiCDN.Vendor)
	require.Equal(t, "huawei", huaweiWAF.Vendor)

	// F5 technologies distinguish BIG-IP from Distributed Cloud while the
	// legacy output stays "f5" for both.
	matched, bigip, err := client.CheckWappalyzerResult(map[string]struct{}{"f5 big-ip": {}})
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "f5", bigip.Name)
	require.Equal(t, "f5-bigip", bigip.Identity.ID)

	matched, distributed, err := client.CheckWappalyzerResult(map[string]struct{}{"f5 distributed cloud": {}})
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "f5", distributed.Name)
	require.Equal(t, "f5-distributed-cloud", distributed.Identity.ID)

	// The ambiguous edgesuite.net suffix is pinned deterministically to
	// Akamai even though the raw data also lists it under edgecast.
	matched, edgeResult, err := client.CheckSuffixResult("x.edgesuite.net")
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "akamai", edgeResult.Identity.ID)
}

// TestLegacyReturnsAreUnchanged locks the pre-directory behavior of the
// classic methods so existing callers observe no regression.
func TestLegacyReturnsAreUnchanged(t *testing.T) {
	client := New()

	matched, provider, itemType, err := client.Check(net.ParseIP("23.228.249.1"))
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "cloudfront", provider)
	require.Equal(t, "cdn", itemType)

	matched, provider, itemType, err = client.CheckSuffix("test.cloudfront.net")
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "amazon", provider)
	require.Equal(t, "waf", itemType)

	matched, provider, itemType, err = client.CheckSuffix("my-lb-1.us-east-1.elb.amazonaws.com")
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "amazon", provider)
	require.Equal(t, "waf", itemType)

	matched, provider, err = client.CheckWappalyzer(map[string]struct{}{"cloudfront": {}})
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "amazon", provider)

	// Fallback order cdn -> waf -> cloud stays unchanged for cloudflare.
	matched, provider, itemType, err = client.Check(net.ParseIP("173.245.48.12"))
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "cloudflare", provider)
	require.Equal(t, "waf", itemType)

	// The Result variant reports the same category and fallback order.
	matched, result, err := client.CheckResult(net.ParseIP("173.245.48.12"))
	require.NoError(t, err)
	require.True(t, matched)
	require.Equal(t, "waf", result.Type)
	require.Equal(t, "cloudflare", result.Name)
}

func TestStableProductIDLists(t *testing.T) {
	cdnIDs := DefaultCDNProductIDs()
	require.True(t, sort.StringsAreSorted(cdnIDs))
	require.Contains(t, cdnIDs, "amazon-cloudfront")
	require.Contains(t, cdnIDs, "google-cloud-cdn")
	require.NotContains(t, cdnIDs, "google-cloud")

	cloudIDs := DefaultCloudProductIDs()
	require.Contains(t, cloudIDs, "amazon-aws")
	require.Contains(t, cloudIDs, "google-cloud")

	wafIDs := DefaultWAFProductIDs()
	require.Contains(t, wafIDs, "imperva-incapsula")
}

func TestMergeIdentityDirectories(t *testing.T) {
	base := DefaultIdentityDirectory()
	override := &IdentityDirectory{
		Entries: []IdentityEntry{
			{ID: "amazon-cloudfront", Vendor: "amazon", Product: "cloudfront-edge", Aliases: []string{"cloudfront"}},
			{ID: "new-vendor-product", Vendor: "new-vendor", Product: "product", Aliases: []string{"new-vendor"}},
		},
		Suffixes:     map[string]string{"example.net": "new-vendor-product"},
		Technologies: map[string]string{"cloudfront": "amazon-cloudfront"},
	}

	merged := MergeIdentityDirectories(base, override)
	entries, _, _ := normalizeDirectory(merged)
	require.Len(t, entries, len(base.Entries)+1)
	require.Equal(t, "cloudfront-edge", entries["amazon-cloudfront"].Product)
	require.Equal(t, "new-vendor-product", entries["new-vendor-product"].ID)
	require.Equal(t, "new-vendor-product", merged.Suffixes["example.net"])
	require.Equal(t, "amazon-cloudfront", merged.Suffixes["cloudfront.net"], "base suffixes are retained")
	require.NoError(t, ValidateIdentityDirectory(merged))

	// Nil override returns an equivalent copy of the base.
	copyOnly := MergeIdentityDirectories(base, nil)
	baseEntries, baseSuffixes, baseTech := normalizeDirectory(base)
	copyEntries, copySuffixes, copyTech := normalizeDirectory(copyOnly)
	require.True(t, reflect.DeepEqual(baseEntries, copyEntries))
	require.True(t, reflect.DeepEqual(baseSuffixes, copySuffixes))
	require.True(t, reflect.DeepEqual(baseTech, copyTech))
}

func TestInvalidDirectoryRejected(t *testing.T) {
	require.Error(t, ValidateIdentityDirectory(&IdentityDirectory{
		Entries: []IdentityEntry{
			{ID: "a", Vendor: "v", Aliases: []string{"shared"}},
			{ID: "b", Vendor: "w", Aliases: []string{"shared"}},
		},
	}))
	require.Error(t, ValidateIdentityDirectory(&IdentityDirectory{
		Entries:      []IdentityEntry{{ID: "a", Vendor: "v"}},
		Suffixes:     map[string]string{"x.net": "missing"},
		Technologies: map[string]string{},
	}))
}
