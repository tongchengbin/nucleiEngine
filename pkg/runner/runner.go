package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/projectdiscovery/nuclei/v2/pkg/core/inputs/hybrid"
	"github.com/projectdiscovery/retryablehttp-go"
	uncoverlib "github.com/projectdiscovery/uncover"
	permissionutil "github.com/projectdiscovery/utils/permission"
	updateutils "github.com/projectdiscovery/utils/update"
	"net/http"
	_ "net/http/pprof"
	"nuclei-engine/pkg/colorizer"
	"nuclei-engine/pkg/core"
	"nuclei-engine/pkg/runner/nucleicloud"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"time"

	"github.com/logrusorgru/aurora"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/ratelimit"

	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/config"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/disk"
	"github.com/projectdiscovery/nuclei/v2/pkg/catalog/loader"
	"github.com/projectdiscovery/nuclei/v2/pkg/input"
	"github.com/projectdiscovery/nuclei/v2/pkg/output"
	"github.com/projectdiscovery/nuclei/v2/pkg/parsers"
	"github.com/projectdiscovery/nuclei/v2/pkg/progress"
	"github.com/projectdiscovery/nuclei/v2/pkg/projectfile"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/hosterrorscache"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/interactsh"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/uncover"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/utils/excludematchers"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/headless/engine"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/http/httpclientpool"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/jsonexporter"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/jsonl"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/markdown"
	"github.com/projectdiscovery/nuclei/v2/pkg/reporting/exporters/sarif"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/stats"
	"github.com/projectdiscovery/nuclei/v2/pkg/utils/yaml"
)

type Target struct {
	URL  string
	Tags []string
}

// Runner is a client for running the enumeration process.
type Runner struct {
	output            output.Writer
	interactsh        *interactsh.Client
	options           *types.Options
	projectFile       *projectfile.ProjectFile
	catalog           catalog.Catalog
	progress          progress.Progress
	colorizer         aurora.Aurora
	issuesClient      reporting.Client
	hmapInputProvider *hybrid.Input
	browser           *engine.Browser
	rateLimiter       *ratelimit.Limiter
	hostErrors        hosterrorscache.CacheInterface
	resumeCfg         *types.ResumeCfg
	pprofServer       *http.Server
	cloudClient       *nucleicloud.Client
	cloudTargets      []string

	Targets chan *Target
}

const pprofServerAddress = "127.0.0.1:8086"

// New creates a new client for running the enumeration process.
func New(options *types.Options) (*Runner, error) {
	runner := &Runner{
		Targets: make(chan *Target, 100000),
		options: options,
	}
	parsers.NoStrictSyntax = options.NoStrictSyntax
	yaml.StrictSyntax = !options.NoStrictSyntax
	runner.catalog = disk.NewCatalog(config.DefaultConfig.TemplatesDirectory)
	var httpclient *retryablehttp.Client
	if options.ProxyInternal && types.ProxyURL != "" || types.ProxySocksURL != "" {
		var err error
		httpclient, err = httpclientpool.Get(options, &httpclientpool.Configuration{})
		if err != nil {
			return nil, err
		}
	}
	if err := reporting.CreateConfigIfNotExists(); err != nil {
		return nil, err
	}
	reportingOptions, err := createReportingOptions(options)
	if err != nil {
		return nil, err
	}
	if reportingOptions != nil && httpclient != nil {
		reportingOptions.HttpClient = httpclient
	}

	if reportingOptions != nil {
		client, err := reporting.New(reportingOptions, options.ReportingDB)
		if err != nil {
			return nil, errors.Wrap(err, "could not create issue reporting client")
		}
		runner.issuesClient = client
	}
	// output coloring
	useColor := !options.NoColor
	runner.colorizer = aurora.NewAurora(useColor)
	templates.Colorizer = runner.colorizer
	templates.SeverityColorizer = colorizer.New(runner.colorizer)

	if options.EnablePprof {
		server := &http.Server{
			Addr:    pprofServerAddress,
			Handler: http.DefaultServeMux,
		}
		gologger.Info().Msgf("Listening pprof debug server on: %s", pprofServerAddress)
		runner.pprofServer = server
		go func() {
			_ = server.ListenAndServe()
		}()
	}

	// Create the output file if asked
	outputWriter, err := output.NewStandardWriter(options)
	if err != nil {
		return nil, errors.Wrap(err, "could not create output file")
	}
	runner.output = outputWriter

	if options.JSONL && options.EnableProgressBar {
		options.StatsJSON = true
	}
	if options.StatsJSON {
		options.EnableProgressBar = true
	}
	// Creates the progress tracking object
	var progressErr error
	statsInterval := options.StatsInterval
	if options.Cloud && !options.EnableProgressBar {
		statsInterval = -1
		options.EnableProgressBar = true
	}
	runner.progress, progressErr = progress.NewStatsTicker(statsInterval, options.EnableProgressBar, options.StatsJSON, options.Metrics, options.Cloud, options.MetricsPort)
	if progressErr != nil {
		return nil, progressErr
	}

	// create project file if requested or load the existing one
	if options.Project {
		var projectFileErr error
		runner.projectFile, projectFileErr = projectfile.New(&projectfile.Options{Path: options.ProjectPath, Cleanup: utils.IsBlank(options.ProjectPath)})
		if projectFileErr != nil {
			return nil, projectFileErr
		}
	}

	// create the resume configuration structure
	resumeCfg := types.NewResumeCfg()
	if runner.options.ShouldLoadResume() {
		gologger.Info().Msg("Resuming from save checkpoint")
		file, err := os.ReadFile(runner.options.Resume)
		if err != nil {
			return nil, err
		}
		err = json.Unmarshal(file, &resumeCfg)
		if err != nil {
			return nil, err
		}
		resumeCfg.Compile()
	}
	runner.resumeCfg = resumeCfg

	opts := interactsh.DefaultOptions(runner.output, runner.issuesClient, runner.progress)
	opts.Debug = runner.options.Debug
	opts.NoColor = runner.options.NoColor
	if options.InteractshURL != "" {
		opts.ServerURL = options.InteractshURL
	}
	opts.Authorization = options.InteractshToken
	opts.CacheSize = options.InteractionsCacheSize
	opts.Eviction = time.Duration(options.InteractionsEviction) * time.Second
	opts.CooldownPeriod = time.Duration(options.InteractionsCoolDownPeriod) * time.Second
	opts.PollDuration = time.Duration(options.InteractionsPollDuration) * time.Second
	opts.NoInteractsh = runner.options.NoInteractsh
	opts.StopAtFirstMatch = runner.options.StopAtFirstMatch
	opts.Debug = runner.options.Debug
	opts.DebugRequest = runner.options.DebugRequests
	opts.DebugResponse = runner.options.DebugResponse
	if httpclient != nil {
		opts.HTTPClient = httpclient
	}
	if opts.HTTPClient == nil {
		httpOpts := retryablehttp.DefaultOptionsSingle
		httpOpts.Timeout = 20 * time.Second // for stability reasons
		if options.Timeout > 20 {
			httpOpts.Timeout = time.Duration(options.Timeout) * time.Second
		}
		// in testing it was found most of times when interactsh failed, it was due to failure in registering /polling requests
		opts.HTTPClient = retryablehttp.NewClient(retryablehttp.DefaultOptionsSingle)
	}
	interactshClient, err := interactsh.New(opts)
	if err != nil {
		gologger.Error().Msgf("Could not create interactsh client: %s", err)
	} else {
		runner.interactsh = interactshClient
	}

	if options.RateLimitMinute > 0 {
		runner.rateLimiter = ratelimit.New(context.Background(), uint(options.RateLimitMinute), time.Minute)
	} else if options.RateLimit > 0 {
		runner.rateLimiter = ratelimit.New(context.Background(), uint(options.RateLimit), time.Second)
	} else {
		runner.rateLimiter = ratelimit.NewUnlimited(context.Background())
	}
	return runner, nil
}

func createReportingOptions(options *types.Options) (*reporting.Options, error) {
	var reportingOptions *reporting.Options
	if options.ReportingConfig != "" {
		file, err := os.Open(options.ReportingConfig)
		if err != nil {
			return nil, errors.Wrap(err, "could not open reporting config file")
		}
		defer file.Close()

		reportingOptions = &reporting.Options{}
		if err := yaml.DecodeAndValidate(file, reportingOptions); err != nil {
			return nil, errors.Wrap(err, "could not parse reporting config file")
		}
		Walk(reportingOptions, expandEndVars)
	}
	if options.MarkdownExportDirectory != "" {
		if reportingOptions != nil {
			reportingOptions.MarkdownExporter = &markdown.Options{
				Directory:         options.MarkdownExportDirectory,
				IncludeRawPayload: !options.OmitRawRequests,
				SortMode:          options.MarkdownExportSortMode,
			}
		} else {
			reportingOptions = &reporting.Options{}
			reportingOptions.MarkdownExporter = &markdown.Options{
				Directory:         options.MarkdownExportDirectory,
				IncludeRawPayload: !options.OmitRawRequests,
				SortMode:          options.MarkdownExportSortMode,
			}
		}
	}
	if options.SarifExport != "" {
		if reportingOptions != nil {
			reportingOptions.SarifExporter = &sarif.Options{File: options.SarifExport}
		} else {
			reportingOptions = &reporting.Options{}
			reportingOptions.SarifExporter = &sarif.Options{File: options.SarifExport}
		}
	}
	if options.JSONExport != "" {
		if reportingOptions != nil {
			reportingOptions.JSONExporter = &jsonexporter.Options{
				File:              options.JSONExport,
				IncludeRawPayload: !options.OmitRawRequests,
			}
		} else {
			reportingOptions = &reporting.Options{}
			reportingOptions.JSONExporter = &jsonexporter.Options{
				File:              options.JSONExport,
				IncludeRawPayload: !options.OmitRawRequests,
			}
		}
	}
	if options.JSONLExport != "" {
		if reportingOptions != nil {
			reportingOptions.JSONLExporter = &jsonl.Options{
				File:              options.JSONLExport,
				IncludeRawPayload: !options.OmitRawRequests,
			}
		} else {
			reportingOptions = &reporting.Options{}
			reportingOptions.JSONLExporter = &jsonl.Options{
				File:              options.JSONLExport,
				IncludeRawPayload: !options.OmitRawRequests,
			}
		}
	}

	return reportingOptions, nil
}

// Close releases all the resources and cleans up
func (r *Runner) Close() {
	if r.output != nil {
		r.output.Close()
	}
	if r.projectFile != nil {
		r.projectFile.Close()
	}
	protocolinit.Close()
	if r.pprofServer != nil {
		_ = r.pprofServer.Shutdown(context.Background())
	}
	if r.rateLimiter != nil {
		r.rateLimiter.Stop()
	}
}

func (r *Runner) InitAsyncConfig() (*loader.Store, error) {
	// 初始化参数 加载所有模板
	executorOpts := protocols.ExecutorOptions{
		Output:          r.output,
		Options:         r.options,
		Progress:        r.progress,
		Catalog:         r.catalog,
		IssuesClient:    r.issuesClient,
		RateLimiter:     r.rateLimiter,
		Interactsh:      r.interactsh,
		ProjectFile:     r.projectFile,
		Browser:         r.browser,
		Colorizer:       r.colorizer,
		ResumeCfg:       r.resumeCfg,
		ExcludeMatchers: excludematchers.New(r.options.ExcludeMatchers),
		InputHelper:     input.NewHelper(),
	}

	if r.options.ShouldUseHostError() {
		cache := hosterrorscache.New(r.options.MaxHostError, hosterrorscache.DefaultMaxHostsCount, r.options.TrackError)
		cache.SetVerbose(r.options.Verbose)
		r.hostErrors = cache
		executorOpts.HostErrorsCache = cache
	}

	workflowLoader, err := parsers.NewLoader(&executorOpts)
	if err != nil {
		return nil, errors.Wrap(err, "Could not create loader.")
	}
	executorOpts.WorkflowLoader = workflowLoader
	store, err := loader.New(loader.NewConfig(r.options, r.catalog, executorOpts))
	if err != nil {
		return nil, errors.Wrap(err, "could not load templates from config")
	}
	if r.options.Validate {
		if err := store.ValidateTemplates(); err != nil {
			return nil, err
		}
		if stats.GetValue(parsers.SyntaxErrorStats) == 0 && stats.GetValue(parsers.SyntaxWarningStats) == 0 && stats.GetValue(parsers.RuntimeWarningsStats) == 0 {
			gologger.Info().Msgf("All templates validated successfully\n")
		} else {
			return nil, errors.New("encountered errors while performing template validation")
		}
		return nil, nil // exit
	}
	store.Load()
	return store, nil
}

func (r *Runner) RunEnumerationAsync(store *loader.Store) error {
	// Create the executor options which will be used throughout the execution
	// stage by the nuclei engine modules.
	// Create the executor options which will be used throughout the execution
	// stage by the nuclei engine modules.

	// Create the output file if asked
	outputWriter, err := output.NewStandardWriter(r.options)
	if err != nil {
		return errors.Wrap(err, "could not create output file")
	}

	// TODO: remove below functions after v3 or update warning messages
	disk.PrintDeprecatedPathsMsgIfApplicable(r.options.Silent)
	templates.PrintDeprecatedProtocolNameMsgIfApplicable(r.options.Silent, r.options.Verbose)

	// add the hosts from the metadata queries of loaded templates into input provider
	if r.options.Uncover && len(r.options.UncoverQuery) == 0 {
		uncoverOpts := &uncoverlib.Options{
			Limit:         r.options.UncoverLimit,
			MaxRetry:      r.options.Retries,
			Timeout:       r.options.Timeout,
			RateLimit:     uint(r.options.UncoverRateLimit),
			RateLimitUnit: time.Minute, // default unit is minute
		}
		ret := uncover.GetUncoverTargetsFromMetadata(context.TODO(), store.Templates(), r.options.UncoverField, uncoverOpts)
		for host := range ret {
			r.hmapInputProvider.Set(host)
		}
	}
	// list all templates
	if r.options.TemplateList || r.options.TemplateDisplay {
		r.listAvailableStoreTemplates(store)
		os.Exit(0)
	}

	// display execution info like version , templates used etc
	//r.displayExecutionInfo(store)
	// If not explicitly disabled, check if http based protocols
	// are used, and if inputs are non-http to pre-perform probing
	// of urls and storing them for execution.
	// 初始化参数 加载所有模板
	executorOpts := protocols.ExecutorOptions{
		Output:          r.output,
		Options:         r.options,
		Progress:        r.progress,
		Catalog:         r.catalog,
		IssuesClient:    r.issuesClient,
		RateLimiter:     r.rateLimiter,
		Interactsh:      r.interactsh,
		ProjectFile:     r.projectFile,
		Browser:         r.browser,
		Colorizer:       r.colorizer,
		ResumeCfg:       r.resumeCfg,
		ExcludeMatchers: excludematchers.New(r.options.ExcludeMatchers),
		InputHelper:     input.NewHelper(),
	}

	executorEngine := core.New(r.options)
	executorEngine.SetExecuterOptions(executorOpts)
	executorEngine.Callback = func(event *output.ResultEvent) {
		_ = outputWriter.Write(event)
	}
	for target := range r.Targets {
		var finalTemplates []*templates.Template
		for _, template := range store.Templates() {
			templateTags := template.Info.Tags.ToSlice()
			for _, templateTag := range templateTags {
				for _, targetTag := range target.Tags {
					if templateTag == targetTag {
						finalTemplates = append(finalTemplates, template)
						break
					}
				}
			}
		}
		results := &atomic.Bool{}
		executorEngine.ExecuteTemplatesOnTarget(finalTemplates, &contextargs.MetaInput{Input: target.URL}, results)
		fmt.Println(target, len(finalTemplates))
	}
	return nil
}

func (r *Runner) isInputNonHTTP() bool {
	var nonURLInput bool
	r.hmapInputProvider.Scan(func(value *contextargs.MetaInput) bool {
		if !strings.Contains(value.Input, "://") {
			nonURLInput = true
			return false
		}
		return true
	})
	return nonURLInput
}

// displayExecutionInfo displays misc info about the nuclei engine execution
func (r *Runner) displayExecutionInfo(store *loader.Store) {
	// Display stats for any loaded templates' syntax warnings or errors
	stats.Display(parsers.SyntaxWarningStats)
	stats.Display(parsers.SyntaxErrorStats)
	stats.Display(parsers.RuntimeWarningsStats)

	cfg := config.DefaultConfig

	gologger.Info().Msgf("Current nuclei version: %v %v", config.Version, updateutils.GetVersionDescription(config.Version, cfg.LatestNucleiVersion))
	gologger.Info().Msgf("Current nuclei-templates version: %v %v", cfg.TemplateVersion, updateutils.GetVersionDescription(cfg.TemplateVersion, cfg.LatestNucleiTemplatesVersion))

	if len(store.Templates()) > 0 {
		gologger.Info().Msgf("New templates added in latest release: %d", len(config.DefaultConfig.GetNewAdditions()))
		gologger.Info().Msgf("Templates loaded for current scan: %d", len(store.Templates()))
	}
	if len(store.Workflows()) > 0 {
		gologger.Info().Msgf("Workflows loaded for current scan: %d", len(store.Workflows()))
	}
	if r.hmapInputProvider.Count() > 0 {
		gologger.Info().Msgf("Targets loaded for current scan: %d", r.hmapInputProvider.Count())
	}
}

// SaveResumeConfig to file
func (r *Runner) SaveResumeConfig(path string) error {
	resumeCfgClone := r.resumeCfg.Clone()
	resumeCfgClone.ResumeFrom = resumeCfgClone.Current
	data, _ := json.MarshalIndent(resumeCfgClone, "", "\t")

	return os.WriteFile(path, data, permissionutil.ConfigFilePermission)
}

type WalkFunc func(reflect.Value, reflect.StructField)

// Walk traverses a struct and executes a callback function on each value in the struct.
// The interface{} passed to the function should be a pointer to a struct or a struct.
// WalkFunc is the callback function used for each value in the struct. It is passed the
// reflect.Value and reflect.Type properties of the value in the struct.
func Walk(s interface{}, callback WalkFunc) {
	structValue := reflect.ValueOf(s)
	if structValue.Kind() == reflect.Ptr {
		structValue = structValue.Elem()
	}
	if structValue.Kind() != reflect.Struct {
		return
	}
	for i := 0; i < structValue.NumField(); i++ {
		field := structValue.Field(i)
		fieldType := structValue.Type().Field(i)
		if !fieldType.IsExported() {
			continue
		}
		if field.Kind() == reflect.Struct {
			Walk(field.Addr().Interface(), callback)
		} else if field.Kind() == reflect.Ptr && field.Elem().Kind() == reflect.Struct {
			Walk(field.Interface(), callback)
		} else {
			callback(field, fieldType)
		}
	}
}

// expandEndVars looks for values in a struct tagged with "yaml" and checks if they are prefixed with '$'.
// If they are, it will try to retrieve the value from the environment and if it exists, it will set the
// value of the field to that of the environment variable.
func expandEndVars(f reflect.Value, fieldType reflect.StructField) {
	if _, ok := fieldType.Tag.Lookup("yaml"); !ok {
		return
	}
	if f.Kind() == reflect.String {
		str := f.String()
		if strings.HasPrefix(str, "$") {
			env := strings.TrimPrefix(str, "$")
			retrievedEnv := os.Getenv(env)
			if retrievedEnv != "" {
				f.SetString(os.Getenv(env))
			}
		}
	}
}

func (r *Runner) AddTagTarget(target string, tags []string) {
	r.Targets <- &Target{URL: target, Tags: tags}

}
func (r *Runner) Wait() {
	close(r.Targets)
}
