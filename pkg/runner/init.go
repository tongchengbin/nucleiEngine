package runner

import (
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/protocolstate"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/types"
	"reflect"
	"regexp"
	"strings"
)

// allTagsRegex is a list of all tags in nuclei templates except id, info, and -
var allTagsRegex []*regexp.Regexp

func init() {
	var tm templates.Template
	t := reflect.TypeOf(tm)
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("yaml")
		if strings.Contains(tag, ",") {
			tag = strings.Split(tag, ",")[0]
		}
		// ignore these tags
		if tag == "id" || tag == "info" || tag == "" || tag == "-" {
			continue
		}
		re := regexp.MustCompile(tag + `:\s*\n`)
		if t.Field(i).Type.Kind() == reflect.Bool {
			re = regexp.MustCompile(tag + `:\s*(true|false)\s*\n`)
		}
		allTagsRegex = append(allTagsRegex, re)
	}

	defaultOpts := types.DefaultOptions()
	// need to set headless to true for headless templates
	defaultOpts.Headless = true
	if err := protocolstate.Init(defaultOpts); err != nil {
		gologger.Fatal().Msgf("Could not initialize protocol state: %s\n", err)
	}
	if err := protocolinit.Init(defaultOpts); err != nil {
		gologger.Fatal().Msgf("Could not initialize protocol state: %s\n", err)
	}
}
