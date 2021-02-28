package judge

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"os"
	"strings"
	"text/template"

	"github.com/open-policy-agent/opa/rego"
	"github.com/rakyll/statik/fs"
	"github.com/rs/zerolog/log"

	_ "github.com/doitintl/kube-no-trouble/generated/statik"
)

type RegoJudge struct {
	preparedQuery rego.PreparedEvalQuery
}

type RegoOpts struct {
}

func NewRegoJudge(opts *RegoOpts, additionalResourcesStr []string) (*RegoJudge, error) {
	ctx := context.Background()

	var additionalKinds []schema.GroupVersionKind
	for _, ar := range additionalResourcesStr {
		gvr, _ := schema.ParseKindArg(ar)
		additionalKinds = append(additionalKinds, *gvr)
	}

	r := rego.New(
		rego.Query("data[_].main"),
	)

	statikFS, err := fs.New()

	err = fs.Walk(statikFS, "/",
		func(path string, info os.FileInfo, err error) error {
			log.Debug().Msgf("Walking file: %s", info.Name())
			if !info.IsDir() {
				if err != nil {
					return err
				}
				f, err := statikFS.Open(path)
				if err != nil {
					return err
				}
				c, err := ioutil.ReadAll(f)
				if err != nil {
					return err
				}

				switch {
				case strings.HasSuffix(info.Name(), ".rego"):
					rego.Module(info.Name(), string(c))(r)
					log.Info().Str("name", info.Name()).Msg("Loaded ruleset")

				// currently this is relevant only to additional resources
				case strings.HasSuffix(info.Name(), ".tmpl"):
					t, err := template.New(info.Name()).Parse(string(c))
					if err != nil {
						return fmt.Errorf("failed to parse template %s: %w", info.Name(), err)
					}

					var tpl bytes.Buffer
					if err := t.Execute(&tpl, additionalKinds); err != nil {
						return fmt.Errorf("failed to render template %s: %w", info.Name(), err)
					}

					rego.Module(info.Name(), tpl.String())(r)
					log.Info().Str("name", info.Name()).Msg("Rendered and loaded ruleset")

				default:
					return fmt.Errorf("unrecognized filetype: %s", info.Name())
				}
			}
			return nil
		})
	if err != nil {
		return nil, err
	}

	pq, err := r.PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}

	judge := &RegoJudge{preparedQuery: pq}
	return judge, nil
}

func (j *RegoJudge) Eval(input []map[string]interface{}) ([]Result, error) {
	ctx := context.Background()

	log.Debug().Msgf("evaluating +%v", input)
	rs, err := j.preparedQuery.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}

	results := []Result{}
	for _, r := range rs {
		for _, e := range r.Expressions {
			for _, i := range e.Value.([]interface{}) {
				m := i.(map[string]interface{})
				results = append(results, Result{
					Name:        m["Name"].(string),
					Namespace:   m["Namespace"].(string),
					Kind:        m["Kind"].(string),
					ApiVersion:  m["ApiVersion"].(string),
					ReplaceWith: m["ReplaceWith"].(string),
					RuleSet:     m["RuleSet"].(string),
					Since:       m["Since"].(string),
				})
			}
		}
	}

	return results, nil
}
