package engine

import (
	"context"
	"path"

	"github.com/rezmoss/ip-watch/internal/nginx"
	"github.com/rezmoss/ip-watch/internal/transport"
)

// Nginx: allow/deny in server block, via managed include.
type Nginx struct{}

func (Nginx) Name() string { return "nginx" }

func (Nginx) Detect(ctx context.Context, tr transport.Transport) (*Detection, error) {
	det, err := nginx.Detect(ctx, tr)
	if err != nil {
		return nil, err
	}
	return &Detection{
		Found: det.Found, Binary: det.Binary, Version: det.Version,
		ConfigPath: det.ConfigPath, Message: det.Message,
	}, nil
}

func (e Nginx) Apply(ctx context.Context, tr transport.Transport, in Input) Outcome {
	plan, out, ok := e.plan(ctx, tr, in)
	if !ok {
		return out
	}
	return applyConfig(ctx, tr, in, plan)
}

func (e Nginx) Remove(ctx context.Context, tr transport.Transport, in Input) Outcome {
	plan, out, ok := e.plan(ctx, tr, in)
	if !ok {
		return out
	}
	return removeConfig(ctx, tr, plan)
}

func (Nginx) plan(ctx context.Context, tr transport.Transport, in Input) (configPlan, Outcome, bool) {
	det, err := nginx.Detect(ctx, tr)
	if err != nil || !det.Found {
		return configPlan{}, fail("nginx not detected: %s", detectMessage(err, det.Message)), false
	}
	confFile := in.Target.Config.File
	if confFile == "" {
		confFile = det.ConfigPath
	}
	if confFile == "" {
		return configPlan{}, fail("could not determine nginx config file; set config.file"), false
	}
	managedPath := path.Join(path.Dir(det.ConfigPath), "ip-watch", in.Target.ID+".conf")
	var managedData []byte
	if in.CIDRs != nil {
		managedData = []byte(nginx.RenderInclude(in.Target, in.CIDRs))
	}
	return configPlan{
		bin:         det.Binary,
		managedPath: managedPath,
		managedData: managedData,
		confFile:    confFile,
		reference:   "include " + managedPath + ";",
		selector:    in.Target.Config.Selector,
		inject:      nginx.InjectInclude,
		validate: func(ctx context.Context, tr transport.Transport, bin string) (string, bool, error) {
			return nginx.Validate(ctx, tr, bin)
		},
		reload: func(ctx context.Context, tr transport.Transport, bin string) (string, error) {
			return nginx.Reload(ctx, tr, bin)
		},
	}, Outcome{}, true
}

func detectMessage(err error, msg string) string {
	if err != nil {
		return err.Error()
	}
	if msg != "" {
		return msg
	}
	return "not found"
}
