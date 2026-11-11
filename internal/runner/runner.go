package runner

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/cdncheck"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/mapcidr"
	iputils "github.com/projectdiscovery/utils/ip"
)

type Runner struct {
	options   *Options
	cdnclient *cdncheck.Client
	aurora    *aurora.Aurora
	writer    *OutputWriter
}

func NewRunner(options *Options) *Runner {
	standardWriter := aurora.NewAurora(!options.NoColor)
	client, err := cdncheck.NewWithOpts(options.MaxRetries, options.Resolvers)
	if err != nil {
		gologger.Fatal().Msgf("failed to create cdncheck client: %v", err)
	}
	runner := &Runner{
		options:   options,
		cdnclient: client,
		aurora:    &standardWriter,
	}
	return runner
}

func (r *Runner) Run() error {
	err := r.configureOutput()
	if err != nil {
		return errors.Wrap(err, "could not configure output")
	}
	defer r.writer.Close()
	threads := r.options.Threads
	if threads <= 0 {
		threads = 1
	}
	output := make(chan Output, threads)
	wg := &sync.WaitGroup{}
	wg.Add(1)
	go r.process(output, wg)
	wg.Add(1)
	go r.waitForData(output, wg)
	wg.Wait()
	return nil
}

func (r *Runner) SetWriter(writer io.Writer) error {
	outputWriter, err := NewOutputWriter()
	if err != nil {
		return err
	}
	outputWriter.AddWriters(writer)
	r.writer = outputWriter
	return nil
}

func (r *Runner) process(output chan Output, wg *sync.WaitGroup) {
	defer wg.Done()
	defer close(output)

	threads := r.options.Threads
	if threads <= 0 {
		threads = 1
	}

	tasks := make(chan string, threads)
	var workerWg sync.WaitGroup

	for i := 0; i < threads; i++ {
		workerWg.Add(1)
		go func() {
			defer workerWg.Done()
			for item := range tasks {
				r.processInputItemSingle(item, output)
			}
		}()
	}

	sendItem := func(input string) {
		if _, ipRange, _ := net.ParseCIDR(input); ipRange != nil {
			cidrInputs, err := mapcidr.IPAddressesAsStream(input)
			if err != nil {
				if r.options.Verbose {
					gologger.Error().Msgf("Could not parse cidr %s: %s", input, err)
				}
				return
			}
			for cidr := range cidrInputs {
				tasks <- cidr
			}
		} else {
			tasks <- input
		}
	}

	for _, target := range r.options.Inputs {
		sendItem(target)
	}
	if r.options.HasStdin {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			text := scanner.Text()
			if text != "" {
				sendItem(text)
			}
		}
	}

	close(tasks)
	workerWg.Wait()
}

func (r *Runner) waitForData(output chan Output, wg *sync.WaitGroup) {
	defer wg.Done()
	var cdnCount, wafCount, cloudCount int
	for receivedData := range output {
		if receivedData.Cdn {
			cdnCount++
		} else if receivedData.Waf {
			wafCount++
		} else if receivedData.Cloud {
			cloudCount++
		}

		if r.options.OnResult != nil {
			r.options.OnResult(receivedData)
		}

		if r.options.Json {
			r.writer.WriteJSON(receivedData)
		} else if r.options.Response && !r.options.Exclude {
			r.writer.WriteString(receivedData.String())
		} else {
			r.writer.WriteString(receivedData.Input)
		}
	}

	// show summary to user
	sw := *r.aurora
	if (cdnCount + wafCount + cloudCount) < 1 {
		gologger.Info().Msgf("No results found.")
		return
	}
	var builder strings.Builder
	_, _ = fmt.Fprintf(&builder, "Found result: %v", (cdnCount + cloudCount + wafCount))
	builder.WriteString(" (")
	if cdnCount > 0 {
		_, _ = fmt.Fprintf(&builder, "%s %v", sw.BrightBlue("CDN:").String(), cdnCount)
	}
	if cloudCount > 0 {
		if cdnCount > 0 {
			builder.WriteString(", ")
		}
		_, _ = fmt.Fprintf(&builder, "%s %v", sw.BrightGreen("CLOUD:").String(), cloudCount)
	}
	if wafCount > 0 {
		if cdnCount > 0 || cloudCount > 0 {
			builder.WriteString(", ")
		}
		_, _ = fmt.Fprintf(&builder, "%s %v", sw.Yellow("WAF:").String(), wafCount)
	}
	builder.WriteString(")")
	gologger.Info().Msg(builder.String())
}

func (r *Runner) configureOutput() error {
	if r.writer != nil {
		return nil
	}
	outputWriter, err := NewOutputWriter()
	if err != nil {
		return err
	}
	if r.options.OnResult != nil {
		r.writer = outputWriter
		return nil
	}
	outputWriter.AddWriters(os.Stdout)
	if r.options.Output != "" {
		outputFile, err := os.Create(r.options.Output)
		if err != nil {
			return err
		}
		outputWriter.AddWriters(outputFile)
	}
	r.writer = outputWriter
	return nil
}

func (r *Runner) processInputItemSingle(item string, output chan Output) {
	data := Output{
		aurora: r.aurora,
		Input:  item,
	}

	var matched bool
	var result *cdncheck.Result
	var err error

	var targetIp string
	if iputils.IsIP(item) {
		matched, result, err = r.cdnclient.CheckResult(net.ParseIP(item))
		targetIp = item
	} else {
		matched, result, err = r.cdnclient.CheckDomainWithFallbackResult(item)
		dnsData, dnsErr := r.cdnclient.GetDnsData(item)

		if dnsErr == nil {
			if len(dnsData.AAAA) > 0 {
				targetIp = dnsData.AAAA[0]
			} else if len(dnsData.A) > 0 {
				targetIp = dnsData.A[0]
			}
		}
	}
	if err != nil && r.options.Verbose {
		gologger.Error().Msgf("Could not check domain cdn %s: %s", item, err)
	}

	provider, itemType := "", ""
	if result != nil {
		provider = result.Name
		itemType = result.Type
		if result.Identity != nil {
			data.ProductID = result.Identity.ID
			data.Vendor = result.Identity.Vendor
			data.Product = result.Identity.Product
		}
	}

	data.itemType = itemType
	data.IP = targetIp
	data.Timestamp = time.Now()

	if r.options.Exclude {
		if !matched {
			output <- data
		}
		return
	}

	switch itemType {
	case "cdn":
		data.Cdn = matched
		data.CdnName = provider
	case "cloud":
		data.Cloud = matched
		data.CloudName = provider
	case "waf":
		data.Waf = matched
		data.WafName = provider
	}
	if skipped := filterIP(r.options, r.cdnclient, data); skipped {
		return
	}
	if matched := matchIP(r.options, r.cdnclient, data); !matched {
		return
	}
	switch {
	case r.options.Cdn && data.itemType == "cdn", r.options.Cloud && data.itemType == "cloud", r.options.Waf && data.itemType == "waf":
		{
			output <- data
		}
	case (!r.options.Cdn && !r.options.Waf && !r.options.Cloud) && matched:
		{
			output <- data
		}
	}
}

// identityTokenMatch reports whether a user supplied match/filter token
// applies to a detection. Tokens may be legacy provider names or stable
// product ids/aliases from the identity directory; exact legacy matching is
// always kept as a fallback for names absent from the directory.
func identityTokenMatch(client *cdncheck.Client, token, legacyName, itemType string) bool {
	if token == legacyName {
		return true
	}
	tokenIdentity, tokenOK := client.IdentityOf(token)
	detectedIdentity, detectedOK := client.IdentityFor(legacyName, itemType)
	if tokenOK && detectedOK && tokenIdentity.ID == detectedIdentity.ID {
		return true
	}
	return false
}

func hasMatchingToken(client *cdncheck.Client, tokens []string, legacyName, itemType string) bool {
	for _, token := range tokens {
		if identityTokenMatch(client, token, legacyName, itemType) {
			return true
		}
	}
	return false
}

func matchIP(options *Options, client *cdncheck.Client, data Output) bool {
	if len(options.MatchCdn) == 0 && len(options.MatchCloud) == 0 && len(options.MatchWaf) == 0 {
		return true
	}
	if len(options.MatchCdn) > 0 && data.itemType == "cdn" && hasMatchingToken(client, options.MatchCdn, data.CdnName, "cdn") {
		return true
	}
	if len(options.MatchCloud) > 0 && data.itemType == "cloud" && hasMatchingToken(client, options.MatchCloud, data.CloudName, "cloud") {
		return true
	}
	if len(options.MatchWaf) > 0 && data.itemType == "waf" && hasMatchingToken(client, options.MatchWaf, data.WafName, "waf") {
		return true
	}
	return false
}

func filterIP(options *Options, client *cdncheck.Client, data Output) bool {
	if len(options.FilterCdn) == 0 && len(options.FilterCloud) == 0 && len(options.FilterWaf) == 0 {
		return false
	}
	if len(options.FilterCdn) > 0 && data.itemType == "cdn" && hasMatchingToken(client, options.FilterCdn, data.CdnName, "cdn") {
		return true
	}
	if len(options.FilterCloud) > 0 && data.itemType == "cloud" && hasMatchingToken(client, options.FilterCloud, data.CloudName, "cloud") {
		return true
	}
	if len(options.FilterWaf) > 0 && data.itemType == "waf" && hasMatchingToken(client, options.FilterWaf, data.WafName, "waf") {
		return true
	}
	return false
}
