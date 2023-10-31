package core

import (
	"sync/atomic"

	"github.com/remeh/sizedwaitgroup"

	"github.com/projectdiscovery/nuclei/v2/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates"
	"github.com/projectdiscovery/nuclei/v2/pkg/templates/types"
)

// executeTemplateSpray executes scan using template spray strategy where targets are iterated over each template
func (e *Engine) executeTemplateSpray(templatesList []*templates.Template, target InputProvider) *atomic.Bool {
	results := &atomic.Bool{}

	// wp is workpool that contains different waitgroups for
	// headless and non-headless templates
	wp := e.GetWorkPool()

	for _, template := range templatesList {
		templateType := template.Type()

		var wg *sizedwaitgroup.SizedWaitGroup
		if templateType == types.HeadlessProtocol {
			wg = wp.Headless
		} else {
			wg = wp.Default
		}

		wg.Add()
		go func(tpl *templates.Template) {
			defer wg.Done()
			// All other request types are executed here
			// Note: executeTemplateWithTargets creates goroutines and blocks
			// given template is executed on all targets
			e.executeTemplateWithTargets(tpl, target, results)
		}(template)
	}
	wp.Wait()
	return results
}

// executeHostSpray executes scan using host spray strategy where templates are iterated over each target
func (e *Engine) executeHostSpray(templatesList []*templates.Template, target InputProvider) *atomic.Bool {
	results := &atomic.Bool{}
	wp := sizedwaitgroup.New(e.options.BulkSize + e.options.HeadlessBulkSize)

	target.Scan(func(value *contextargs.MetaInput) bool {
		wp.Add()
		go func(targetval *contextargs.MetaInput) {
			defer wp.Done()
			e.executeTemplatesOnTarget(templatesList, targetval, results)
		}(value)
		return true
	})
	wp.Wait()
	return results
}
