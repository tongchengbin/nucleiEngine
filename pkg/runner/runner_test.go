package runner

import (
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	fileutil "github.com/projectdiscovery/utils/file"
	"github.com/stretchr/testify/assert"
	"os"
	"os/signal"
	"testing"
	"time"
)

func Test_createReportingOptions(t *testing.T) {
	var options types.Options
	options.ReportingConfig = "../../../integration_tests/test-issue-tracker-config1.yaml"
	resultOptions, err := createReportingOptions(&options)

	assert.Nil(t, err)
	assert.Equal(t, resultOptions.AllowList.Severities, severity.Severities{severity.High, severity.Critical})
	assert.Equal(t, resultOptions.DenyList.Severities, severity.Severities{severity.Low})

	options.ReportingConfig = "../../../integration_tests/test-issue-tracker-config2.yaml"
	resultOptions2, err := createReportingOptions(&options)
	assert.Nil(t, err)
	assert.Equal(t, resultOptions2.AllowList.Severities, resultOptions.AllowList.Severities)
	assert.Equal(t, resultOptions2.DenyList.Severities, resultOptions.DenyList.Severities)
}

type TestStruct1 struct {
	A      string       `yaml:"a"`
	Struct *TestStruct2 `yaml:"b"`
}

type TestStruct2 struct {
	B string `yaml:"b"`
}

type TestStruct3 struct {
	A string `yaml:"a"`
	B string `yaml:"b"`
	C string `yaml:"c"`
}

type TestStruct4 struct {
	A      string       `yaml:"a"`
	Struct *TestStruct3 `yaml:"b"`
}

type TestStruct5 struct {
	A []string  `yaml:"a"`
	B [2]string `yaml:"b"`
}

type TestStruct6 struct {
	A string       `yaml:"a"`
	B *TestStruct2 `yaml:"b"`
	C string
}

func TestWalkReflectStructAssignsEnvVars(t *testing.T) {
	testStruct := &TestStruct1{
		A: "$VAR_EXAMPLE",
		Struct: &TestStruct2{
			B: "$VAR_TWO",
		},
	}
	os.Setenv("VAR_EXAMPLE", "value")
	os.Setenv("VAR_TWO", "value2")

	Walk(testStruct, expandEndVars)

	assert.Equal(t, "value", testStruct.A)
	assert.Equal(t, "value2", testStruct.Struct.B)
}

func TestWalkReflectStructHandlesDifferentTypes(t *testing.T) {
	testStruct := &TestStruct3{
		A: "$VAR_EXAMPLE",
		B: "$VAR_TWO",
		C: "$VAR_THREE",
	}
	os.Setenv("VAR_EXAMPLE", "value")
	os.Setenv("VAR_TWO", "2")
	os.Setenv("VAR_THREE", "true")

	Walk(testStruct, expandEndVars)

	assert.Equal(t, "value", testStruct.A)
	assert.Equal(t, "2", testStruct.B)
	assert.Equal(t, "true", testStruct.C)
}

func TestWalkReflectStructEmpty(t *testing.T) {
	testStruct := &TestStruct3{
		A: "$VAR_EXAMPLE",
		B: "",
		C: "$VAR_THREE",
	}
	os.Setenv("VAR_EXAMPLE", "value")
	os.Setenv("VAR_TWO", "2")
	os.Setenv("VAR_THREE", "true")

	Walk(testStruct, expandEndVars)

	assert.Equal(t, "value", testStruct.A)
	assert.Equal(t, "", testStruct.B)
	assert.Equal(t, "true", testStruct.C)
}

func TestWalkReflectStructWithNoYamlTag(t *testing.T) {
	test := &TestStruct6{
		A: "$GITHUB_USER",
		B: &TestStruct2{
			B: "$GITHUB_USER",
		},
		C: "$GITHUB_USER",
	}

	os.Setenv("GITHUB_USER", "testuser")

	Walk(test, expandEndVars)
	assert.Equal(t, "testuser", test.A)
	assert.Equal(t, "testuser", test.B.B, test.B)
	assert.Equal(t, "$GITHUB_USER", test.C)
}

func TestWalkReflectStructHandlesNestedStructs(t *testing.T) {
	testStruct := &TestStruct4{
		A: "$VAR_EXAMPLE",
		Struct: &TestStruct3{
			B: "$VAR_TWO",
			C: "$VAR_THREE",
		},
	}
	os.Setenv("VAR_EXAMPLE", "value")
	os.Setenv("VAR_TWO", "2")
	os.Setenv("VAR_THREE", "true")

	Walk(testStruct, expandEndVars)

	assert.Equal(t, "value", testStruct.A)
	assert.Equal(t, "2", testStruct.Struct.B)
	assert.Equal(t, "true", testStruct.Struct.C)
}

func TestRunner(t *testing.T) {
	options := &types.Options{
		ProjectPath:                os.TempDir(),
		Targets:                    goflags.StringSlice{"http://127.0.0.1:8000"},
		OutputLimit:                100,
		StatsInterval:              5,
		MetricsPort:                9092,
		MaxHostError:               30,
		BulkSize:                   128,
		TemplateThreads:            25,
		HeadlessBulkSize:           10,
		HeadlessTemplateThreads:    10,
		Timeout:                    10,
		Retries:                    1,
		RateLimit:                  150,
		RateLimitMinute:            0,
		PageTimeout:                20,
		InteractionsCacheSize:      5000,
		InteractionsPollDuration:   5,
		InteractionsEviction:       60,
		InteractionsCoolDownPeriod: 5,
		MaxRedirects:               10,
		StoreResponseDir:           "output",
		ResponseReadSize:           10485760,
		ResponseSaveSize:           1048576,
		InputReadTimeout:           180000000000,
		UncoverField:               "ip:port",
		UncoverLimit:               100,
		UncoverRateLimit:           60,
		ScanStrategy:               "auto",
		AutomaticScan:              false,
		Stream:                     false,
	}
	nucleiRunner, err := New(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}
	if nucleiRunner == nil {
		return
	}
	// Setup graceful exits
	resumeFileName := types.DefaultResumeFilePath()
	c := make(chan os.Signal, 1)
	defer close(c)
	signal.Notify(c, os.Interrupt)
	go func() {
		for range c {
			gologger.Info().Msgf("CTRL+C pressed: Exiting\n")
			nucleiRunner.Close()
			if options.ShouldSaveResume() {
				gologger.Info().Msgf("Creating resume file: %s\n", resumeFileName)
				err := nucleiRunner.SaveResumeConfig(resumeFileName)
				if err != nil {
					gologger.Error().Msgf("Couldn't create resume file: %s\n", err)
				}
			}
			os.Exit(1)
		}
	}()
	store, err := nucleiRunner.InitAsyncConfig()

	if err != nil {
		return
	}
	go func() {
		for i := 0; i < 1; i++ {
			time.Sleep(2 * time.Second)
			nucleiRunner.AddTagTarget("http://127.0.0.1:8000", []string{"redirect"})
		}
		nucleiRunner.Wait()
	}()
	if err := nucleiRunner.RunEnumerationAsync(store); err != nil {
		if options.Validate {
			gologger.Fatal().Msgf("Could not validate templates: %s\n", err)
		} else {
			gologger.Fatal().Msgf("Could not run nuclei: %s\n", err)
		}
	}
	nucleiRunner.Close()
	// on successful execution remove the resume file in case it exists
	if fileutil.FileExists(resumeFileName) {
		os.Remove(resumeFileName)
	}
}
