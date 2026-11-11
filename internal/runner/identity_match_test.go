package runner

import (
	"testing"

	"github.com/projectdiscovery/cdncheck"
	"github.com/stretchr/testify/require"
)

func TestMatchAndFilterUseIdentityDirectory(t *testing.T) {
	client := cdncheck.New()

	cloudfrontOutput := Output{itemType: "cdn", CdnName: "cloudfront"}
	incapsulaOutput := Output{itemType: "waf", WafName: "incapsula"}
	googleCloudOutput := Output{itemType: "cloud", CloudName: "google"}

	// Stable product id, legacy name and documented aliases all match.
	for _, token := range []string{"amazon-cloudfront", "cloudfront"} {
		opts := &Options{MatchCdn: []string{token}}
		require.True(t, matchIP(opts, client, cloudfrontOutput), "token %q should match cloudfront cdn", token)
	}
	// The generic amazon vendor identity must NOT match the CloudFront product.
	require.False(t, matchIP(&Options{MatchCdn: []string{"amazon"}}, client, cloudfrontOutput))
	require.False(t, matchIP(&Options{MatchCdn: []string{"amazon-aws"}}, client, cloudfrontOutput))

	// Imperva alias matches the incapsula legacy detection.
	require.True(t, matchIP(&Options{MatchWaf: []string{"imperva"}}, client, incapsulaOutput))
	require.True(t, matchIP(&Options{MatchWaf: []string{"imperva-incapsula"}}, client, incapsulaOutput))
	require.True(t, matchIP(&Options{MatchWaf: []string{"incapsula"}}, client, incapsulaOutput))

	// Category scoped google identity: the cloud product id matches a cloud
	// detection while the cdn product id does not.
	require.True(t, matchIP(&Options{MatchCloud: []string{"google-cloud"}}, client, googleCloudOutput))
	require.False(t, matchIP(&Options{MatchCloud: []string{"google-cloud-cdn"}}, client, googleCloudOutput))
	// Legacy exact matching still works for the shared "google" name.
	require.True(t, matchIP(&Options{MatchCloud: []string{"google"}}, client, googleCloudOutput))

	// Unknown tokens fall back to exact legacy semantics and never match.
	require.False(t, matchIP(&Options{MatchCdn: []string{"unknown-vendor"}}, client, cloudfrontOutput))
	require.True(t, matchIP(&Options{}, client, cloudfrontOutput), "empty matchers match everything")

	// Filters follow the same directory and keep category scoping.
	require.True(t, filterIP(&Options{FilterCdn: []string{"amazon-cloudfront"}}, client, cloudfrontOutput))
	require.True(t, filterIP(&Options{FilterCdn: []string{"cloudfront"}}, client, cloudfrontOutput))
	require.False(t, filterIP(&Options{FilterCdn: []string{"amazon"}}, client, cloudfrontOutput))
	require.False(t, filterIP(&Options{FilterWaf: []string{"imperva-incapsula"}}, client, cloudfrontOutput))
	require.False(t, filterIP(&Options{}, client, cloudfrontOutput), "empty filters never skip")
}
