// Command ip-watch: apply cloud IP ranges to webserver/fw via CLI
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/rezmoss/ip-watch/internal/applier"
	"github.com/rezmoss/ip-watch/internal/config"
	"github.com/rezmoss/ip-watch/internal/docker"
	"github.com/rezmoss/ip-watch/internal/engine"
	"github.com/rezmoss/ip-watch/internal/history"
	"github.com/rezmoss/ip-watch/internal/notify"
	"github.com/rezmoss/ip-watch/internal/provider"
	"github.com/rezmoss/ip-watch/internal/scheduler"
	"github.com/rezmoss/ip-watch/internal/state"
	"github.com/rezmoss/ip-watch/internal/transport"
	"github.com/rezmoss/ip-watch/internal/web"
)

// set via -ldflags; falls back to the module version so `go install …@vX` reports it too
var version = "dev"

func init() {
	if version != "dev" {
		return // stamped by the release build
	}
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
		version = bi.Main.Version
	}
}

// exit non-zero, no err line
var errExitSilent = errors.New("__silent__")

// env passed to each cmd's run
type cmdCtx struct {
	cfg     *config.Config
	cfgPath string
	valid   bool // cfg fully valid
}

type command struct {
	name         string
	group        string
	summary      string
	usage        string
	long         string
	examples     []string
	requireValid bool // refuse if cfg invalid
	noConfig     bool // skip cfg load/validate
	defineFlags  func(*flag.FlagSet)
	run          func(c *command, cx *cmdCtx, args []string) error
}

func main() {
	cfgPath, cmdName, rest, err := parseGlobal(os.Args[1:])
	if err != nil {
		fatalf("%v", err)
	}
	c := lookupCommand(cmdName)
	if c == nil {
		fatalf("unknown command %q — run 'ip-watch help' to see all commands", cmdName)
	}

	cx := &cmdCtx{cfgPath: cfgPath}
	if !c.noConfig {
		cfg, lerr := config.Load(cfgPath)
		if lerr != nil {
			fatalf("config: %v", lerr)
		}
		verr := cfg.Validate()
		if verr != nil {
			fmt.Fprintf(os.Stderr, "ip-watch: config warning: %v\n", verr)
			if c.requireValid {
				os.Exit(1)
			}
		}
		cx.cfg, cx.valid = cfg, verr == nil
	}

	if err := c.run(c, cx, rest); err != nil {
		switch {
		case errors.Is(err, flag.ErrHelp):
			return // help already printed
		case errors.Is(err, errExitSilent):
			os.Exit(1)
		default:
			fatalf("%v", err)
		}
	}
}

// parseGlobal: pull -config (before cmd); ret cmd + rest
func parseGlobal(args []string) (cfgPath, cmd string, rest []string, err error) {
	cfgPath = defaultConfigPath()
	idx := 0
	for idx < len(args) {
		arg := args[idx]
		switch {
		case arg == "-config" || arg == "--config":
			if idx+1 >= len(args) {
				return "", "", nil, fmt.Errorf("-config requires a value")
			}
			cfgPath = args[idx+1]
			idx += 2
		case strings.HasPrefix(arg, "-config="):
			cfgPath, idx = strings.TrimPrefix(arg, "-config="), idx+1
		case strings.HasPrefix(arg, "--config="):
			cfgPath, idx = strings.TrimPrefix(arg, "--config="), idx+1
		case arg == "-h" || arg == "--help":
			return cfgPath, "help", args[idx+1:], nil
		case strings.HasPrefix(arg, "-"):
			return "", "", nil, fmt.Errorf("unknown global flag %q (command-specific flags go AFTER the command; see 'ip-watch help')", arg)
		default:
			return cfgPath, arg, args[idx+1:], nil
		}
	}
	return cfgPath, "serve", nil, nil
}

// cmd registry; built in init to avoid an init cycle
var commands []*command

func init() {
	commands = []*command{
		{
			name: "serve", group: "Run", summary: "Run the web UI + daily scheduler (default command)",
			usage: "ip-watch serve",
			long: "Starts the HTTP UI/API and the scheduler, which applies all enabled targets\n" +
				"on startup and then daily at update_hour. This is the long-running daemon\n" +
				"systemd manages; it is also the default when no command is given.\n\n" +
				"If the config fails validation, serve starts in REPAIR MODE: the web UI runs\n" +
				"so you can fix the config, but the scheduler and startup apply stay disabled\n" +
				"until the config is valid and ip-watch is restarted.",
			examples: []string{"ip-watch serve", "ip-watch -config /etc/ip-watch/config.json serve"},
			run:      runServe,
		},
		{
			name: "detect", group: "Inspect", summary: "Show webserver/firewall engines detected on this host",
			usage: "ip-watch detect", noConfig: true,
			long:     "Probes every engine on the local host and prints, as JSON, which were found\n(binary path + version). Exits non-zero if none are detected.",
			examples: []string{"ip-watch detect", "ip-watch detect | jq 'to_entries[] | select(.value.found)'"},
			run:      runDetect,
		},
		{
			name: "providers", group: "Inspect", summary: "List providers available from the data source",
			usage:    "ip-watch providers",
			long:     "Fetches the provider catalog (summary.json) from data_source and prints each\nprovider's CIDR counts. Use a provider's name with `ip-watch add -provider`.",
			examples: []string{"ip-watch providers", "ip-watch providers | grep -i aws"},
			run:      runProviders,
		},
		{
			name: "config", group: "Inspect", summary: "Print the effective configuration (JSON)",
			usage:    "ip-watch config",
			long:     "Prints the loaded config as JSON, with defaults applied and the auth password\nredacted. Useful to confirm what ip-watch actually sees.",
			examples: []string{"ip-watch config", "ip-watch config | jq .targets"},
			run:      runConfigShow,
		},
		{
			name: "targets", group: "Targets", summary: "List configured targets",
			usage:    "ip-watch targets",
			long:     "Lists every configured target with its mode, engine, transport, providers and\nlast-applied time (from the state store).",
			examples: []string{"ip-watch targets"},
			run:      runTargets,
		},
		{
			name: "add", group: "Targets", summary: "Add or update a target (config only; run 'apply' to enforce)",
			usage: "ip-watch add -id <id> -provider <name> [flags]",
			long: "Creates a target, or replaces an existing one with the same -id. This only\n" +
				"writes the config; nothing is enforced until you run `ip-watch apply` (or pass\n" +
				"-apply to do both). The same validation as the web UI is applied.",
			examples: []string{
				"ip-watch add -id cf -provider cloudflare -engine nginx -selector example.com",
				"ip-watch add -id fw -providers cloudflare,fastly -engine nftables -mode allow -ports 80,443 -admin-allow-ips 203.0.113.5/32",
				"ip-watch add -id ssh -provider cloudflare -engine ufw -ports 22 -allow-admin-ports -apply",
				"ip-watch add -id site -provider cloudflare -engine caddy -transport docker -container caddy -apply",
			},
			defineFlags: defineAddFlags,
			run:         runAddTarget,
		},
		{
			name: "rm", group: "Targets", summary: "Delete a target from config (uninstalls its rules first)",
			usage:    "ip-watch rm <id> [-uninstall=false]",
			long:     "Removes a target from the config. By default its applied rules are torn down\nfirst; pass -uninstall=false to delete the config entry and leave rules in place.",
			examples: []string{"ip-watch rm cf", "ip-watch rm cf -uninstall=false"},
			defineFlags: func(fs *flag.FlagSet) {
				fs.Bool("uninstall", true, "tear down the target's applied rules before deleting")
			},
			run: runRmTarget,
		},
		{
			name: "apply", group: "Apply & enforce", summary: "Apply targets now (all, or one with -target)",
			requireValid: true, // don't enforce invalid cfg
			usage:        "ip-watch apply [-dry] [-target <id>] [-skip-unchanged]",
			long: "Fetches provider ranges and enforces them. Prints a JSON array of per-target\n" +
				"results and exits non-zero if any failed. By default it forces a re-assert of\n" +
				"every enabled target; -skip-unchanged behaves like the daily scheduled run.",
			examples: []string{
				"ip-watch apply",
				"ip-watch apply -dry",
				"ip-watch apply -target cf",
				"ip-watch apply -skip-unchanged",
			},
			defineFlags: func(fs *flag.FlagSet) {
				fs.Bool("dry", false, "preview: render + validate only, no writes or reloads")
				fs.String("target", "", "apply only this target id (default: all enabled)")
				fs.Bool("skip-unchanged", false, "skip targets whose ranges are unchanged since last apply")
			},
			run: runApply,
		},
		{
			name: "remove", group: "Apply & enforce", summary: "Uninstall a target's rules but keep it in config",
			requireValid: true, // don't act on invalid cfg
			usage:        "ip-watch remove [<id>]",
			long:         "Tears down the applied rules for one target (by id) or all targets, leaving the\nconfig untouched. To also delete the config entry, use `ip-watch rm`.",
			examples:     []string{"ip-watch remove cf", "ip-watch remove"},
			run:          runRemove,
		},
		{
			name: "status", group: "Inspect", summary: "Show per-target state and apply counters",
			usage:    "ip-watch status",
			long:     "Summarizes each target: enabled, engine, mode, last-applied time/hash (state\nstore) and apply/change/failure counters (history store).",
			examples: []string{"ip-watch status"},
			run:      runStatus,
		},
		{
			name: "history", group: "Inspect", summary: "Show recent apply history",
			usage:    "ip-watch history [-n <count>] [-json]",
			long:     "Prints the most recent apply events (newest first). Counters and full records\nare available with -json.",
			examples: []string{"ip-watch history", "ip-watch history -n 50", "ip-watch history -json | jq .counters"},
			defineFlags: func(fs *flag.FlagSet) {
				fs.Int("n", 20, "number of recent entries to show")
				fs.Bool("json", false, "output JSON ({recent, counters}) instead of a table")
			},
			run: runHistory,
		},
		{
			name: "metrics", group: "Inspect", summary: "Print Prometheus metrics (same as the /metrics endpoint)",
			usage:    "ip-watch metrics",
			long:     "Renders the Prometheus exposition text from the history store — identical to\nwhat the running server serves at /metrics, but without needing the server.",
			examples: []string{"ip-watch metrics", "ip-watch metrics | grep failures_total"},
			run:      runMetrics,
		},
		{
			name: "settings", group: "Notifications", summary: "Show or change notification settings",
			usage: "ip-watch settings [-webhook <url>] [-always] [-clear]",
			long:  "With no flags, prints the current notification settings. Flags update them and\nsave the config. The webhook is validated (http/https, not loopback/link-local).",
			examples: []string{
				"ip-watch settings",
				"ip-watch settings -webhook https://hooks.slack.com/services/XXX",
				"ip-watch settings -always",
				"ip-watch settings -clear",
			},
			defineFlags: func(fs *flag.FlagSet) {
				fs.String("webhook", "", "set the notification webhook URL")
				fs.Bool("always", false, "notify even when a run changed nothing")
				fs.Bool("clear", false, "clear the configured webhook")
			},
			run: runSettings,
		},
		{
			name: "notify-test", group: "Notifications", summary: "Send a test notification to the configured webhook",
			usage:    "ip-watch notify-test",
			long:     "POSTs a small test payload to the configured webhook so you can confirm it works.",
			examples: []string{"ip-watch notify-test"},
			run:      runNotifyTest,
		},
		{
			name: "docker-ls", group: "Inspect", summary: "List candidate webserver containers on the Docker socket",
			usage:    "ip-watch docker-ls",
			long:     "Discovers running containers that look like webservers ip-watch can manage, for\nuse with `-transport docker -container <name>`.",
			examples: []string{"ip-watch docker-ls"},
			run:      runDockerLs,
		},
		{
			name: "healthcheck", group: "Meta", summary: "Probe a running server's /healthz endpoint",
			usage:    "ip-watch healthcheck",
			long:     "Probes http://<listen>/healthz of a running server and exits non-zero if it is\nnot OK. Used by the Docker HEALTHCHECK (no curl/wget needed).",
			examples: []string{"ip-watch healthcheck"},
			run:      runHealthcheck,
		},
		{
			name: "version", group: "Meta", summary: "Print the version", noConfig: true,
			usage: "ip-watch version", examples: []string{"ip-watch version"},
			run: func(c *command, cx *cmdCtx, args []string) error { fmt.Println("ip-watch", version); return nil },
		},
		{
			name: "help", group: "Meta", summary: "Show help and examples (help <command> for one)", noConfig: true,
			usage: "ip-watch help [command]", examples: []string{"ip-watch help", "ip-watch help add"},
			run: runHelp,
		},
	}
}

func lookupCommand(name string) *command {
	for _, c := range commands {
		if c.name == name {
			return c
		}
	}
	return nil
}

// flags: cmd FlagSet w/ -h help
func (c *command) flags() *flag.FlagSet {
	fs := flag.NewFlagSet("ip-watch "+c.name, flag.ContinueOnError)
	fs.Usage = func() { c.printHelp() }
	if c.defineFlags != nil {
		c.defineFlags(fs)
	}
	return fs
}

func (c *command) printHelp() {
	w := os.Stdout
	fmt.Fprintf(w, "ip-watch %s — %s\n\n", c.name, c.summary)
	if c.usage != "" {
		fmt.Fprintf(w, "Usage:\n  %s\n\n", c.usage)
	}
	if c.long != "" {
		fmt.Fprintf(w, "%s\n\n", strings.TrimSpace(c.long))
	}
	if c.defineFlags != nil {
		fs := flag.NewFlagSet(c.name, flag.ContinueOnError)
		fs.SetOutput(w)
		c.defineFlags(fs)
		fmt.Fprintln(w, "Flags:")
		fs.PrintDefaults()
		fmt.Fprintln(w)
	}
	if len(c.examples) > 0 {
		fmt.Fprintln(w, "Examples:")
		for _, e := range c.examples {
			fmt.Fprintf(w, "  %s\n", e)
		}
		fmt.Fprintln(w)
	}
}

func runHelp(c *command, cx *cmdCtx, args []string) error {
	if len(args) > 0 {
		if t := lookupCommand(args[0]); t != nil {
			t.printHelp()
			return nil
		}
		return fmt.Errorf("unknown command %q", args[0])
	}
	printTopHelp()
	return nil
}

func printTopHelp() {
	w := os.Stdout
	fmt.Fprintln(w, "ip-watch — keep cloud-provider IP ranges applied to a webserver or firewall.")
	fmt.Fprintln(w, "Everything the web UI does is available here. JSON output (apply/detect) is")
	fmt.Fprintln(w, "stable and script/agent friendly.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  ip-watch [-config <path>] <command> [flags]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Global flags:")
	fmt.Fprintln(w, "  -config <path>   config file (default /etc/ip-watch/config.json, or $IPWATCH_CONFIG)")
	fmt.Fprintln(w, "                   must appear BEFORE the command")
	fmt.Fprintln(w)

	groups := []string{"Run", "Targets", "Apply & enforce", "Inspect", "Notifications", "Meta"}
	tw := tabwriter.NewWriter(w, 0, 2, 3, ' ', 0)
	for _, g := range groups {
		fmt.Fprintf(tw, "%s:\t\n", g)
		for _, c := range commands {
			if c.group == g {
				fmt.Fprintf(tw, "  %s\t%s\n", c.name, c.summary)
			}
		}
		fmt.Fprintf(tw, "\t\n")
	}
	tw.Flush()

	fmt.Fprintln(w, "Run 'ip-watch help <command>' or 'ip-watch <command> -h' for details + examples.")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Quick start:")
	fmt.Fprintln(w, "  ip-watch detect                                   # what can I manage here?")
	fmt.Fprintln(w, "  ip-watch providers                                # which providers exist?")
	fmt.Fprintln(w, "  ip-watch add -id cf -provider cloudflare \\")
	fmt.Fprintln(w, "      -engine nginx -selector example.com -apply     # add a target and enforce it")
	fmt.Fprintln(w, "  ip-watch status                                   # did it take effect?")
	fmt.Fprintln(w, "  ip-watch apply                                    # re-assert all targets")
}

func runServe(c *command, cx *cmdCtx, args []string) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if !cx.valid {
		fmt.Fprintln(os.Stderr, "ip-watch: REPAIR MODE — config is invalid; web UI is available to fix it, "+
			"but the scheduler and startup apply are disabled until the config is valid and ip-watch is restarted")
	}
	if cx.valid {
		app := applier.New(cx.cfg, false)
		go scheduler.New(cx.cfg, app).Run(ctx)
	}

	srv := web.New(cx.cfg, cx.cfgPath, version)
	if err := srv.ListenAndServe(ctx); err != nil {
		return fmt.Errorf("web: %w", err)
	}
	return nil
}

func runDetect(c *command, cx *cmdCtx, args []string) error {
	ctx := context.Background()
	tr := transport.NewLocal()
	detections := map[string]*engine.Detection{}
	detected := false
	for _, name := range engine.Names() {
		eng, err := engine.For(name)
		if err != nil {
			continue
		}
		det, err := eng.Detect(ctx, tr)
		if err != nil {
			det = &engine.Detection{Message: err.Error()}
		}
		detections[name] = det
		detected = detected || det.Found
	}
	printJSON(detections)
	if !detected {
		return errExitSilent
	}
	return nil
}

func runProviders(c *command, cx *cmdCtx, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	list, err := provider.New(cx.cfg.DataSource).List(ctx)
	if err != nil {
		return fmt.Errorf("fetching providers: %w", err)
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "PROVIDER\tIPV4\tIPV6\tTOTAL\tSERVICES\tREGIONS")
	for _, p := range list {
		fmt.Fprintf(tw, "%s\t%d\t%d\t%d\t%d\t%d\n", p.Name, p.IPv4CIDRs, p.IPv6CIDRs, p.TotalCIDRs, p.Services, p.Regions)
	}
	return tw.Flush()
}

func runConfigShow(c *command, cx *cmdCtx, args []string) error {
	redacted := *cx.cfg
	if redacted.Auth.Password != "" {
		redacted.Auth.Password = "***"
	}
	printJSON(&redacted)
	return nil
}

func runTargets(c *command, cx *cmdCtx, args []string) error {
	if len(cx.cfg.Targets) == 0 {
		fmt.Println("no targets configured (add one with 'ip-watch add')")
		return nil
	}
	st, _ := state.Load(cx.cfg.StateDir)
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tENABLED\tMODE\tENGINE\tTRANSPORT\tPROVIDERS\tLAST APPLIED")
	for _, t := range cx.cfg.Targets {
		last := "-"
		if st != nil {
			if e, ok := st.Get(t.ID); ok && !e.AppliedAt.IsZero() {
				last = e.AppliedAt.Format(time.RFC3339)
			}
		}
		fmt.Fprintf(tw, "%s\t%v\t%s\t%s\t%s\t%s\t%s\n",
			t.ID, t.Enabled, t.Mode, t.Engine, transportLabel(t), strings.Join(t.EffectiveProviders(), "+"), last)
	}
	return tw.Flush()
}

func defineAddFlags(fs *flag.FlagSet) {
	fs.String("id", "", "target id (required; letters, digits, _ or -)")
	fs.String("provider", "", "single provider name")
	fs.String("providers", "", "comma-separated provider names (merged)")
	fs.String("mode", "allow", "allow (whitelist) | deny (blocklist)")
	fs.String("engine", "nginx", "nginx|caddy|apache|haproxy|nftables|iptables|ufw")
	fs.String("transport", "local", "local | docker")
	fs.String("container", "", "docker: container name or id")
	fs.String("socket", "", "docker: daemon socket path (optional)")
	fs.String("file", "", "config engines: config file (blank = auto-detect)")
	fs.String("selector", "", "config engines: block to edit (server_name/site/frontend)")
	fs.Bool("real-ip", false, "proxy engines: recover the true client IP")
	fs.String("ports", "", "firewall engines: comma-separated TCP ports (default 80,443)")
	fs.Bool("allow-admin-ports", false, "firewall: permit policing management ports in allow mode")
	fs.String("admin-allow-ips", "", "comma-separated CIDRs always allowed in allow mode")
	fs.Bool("enabled", true, "enable the target")
	fs.Bool("apply", false, "apply immediately after saving")
}

func runAddTarget(c *command, cx *cmdCtx, args []string) error {
	fs := c.flags()
	if err := fs.Parse(args); err != nil {
		return err
	}
	id := fstr(fs, "id")
	if id == "" {
		return fmt.Errorf("-id is required (see 'ip-watch help add')")
	}
	provs := splitComma(fstr(fs, "providers"))
	if len(provs) == 0 {
		if p := fstr(fs, "provider"); p != "" {
			provs = []string{p}
		}
	}
	ports, err := parseInts(fstr(fs, "ports"))
	if err != nil {
		return fmt.Errorf("-ports: %w", err)
	}
	t := config.Target{
		ID:            id,
		Providers:     provs,
		Mode:          fstr(fs, "mode"),
		Engine:        fstr(fs, "engine"),
		Transport:     fstr(fs, "transport"),
		Enabled:       fbool(fs, "enabled"),
		Config:        config.ConfigOpts{File: fstr(fs, "file"), Selector: fstr(fs, "selector"), RealIP: fbool(fs, "real-ip")},
		Docker:        config.DockerOpts{Container: fstr(fs, "container"), Socket: fstr(fs, "socket")},
		Firewall:      config.FirewallOpts{Ports: ports, AllowAdminPorts: fbool(fs, "allow-admin-ports")},
		AdminAllowIPs: splitComma(fstr(fs, "admin-allow-ips")),
	}
	if err := t.Validate(); err != nil {
		return err
	}
	if _, err := engine.For(t.Engine); err != nil {
		return err
	}
	if t.Transport == "docker" && t.Docker.Container == "" {
		return fmt.Errorf("docker transport requires -container")
	}

	_, existed := cx.cfg.Target(t.ID)
	if err := applier.GuardConfig(cx.cfg.StateDir, cx.cfg.LockUnsafe, func() error {
		cx.cfg.UpsertTarget(t)
		return cx.cfg.Save(cx.cfgPath)
	}); err != nil {
		return err
	}
	verb := "added"
	if existed {
		verb = "updated"
	}
	fmt.Printf("%s target %q (%s, %s, %s)\n", verb, t.ID, t.Mode, t.Engine, strings.Join(t.EffectiveProviders(), "+"))

	if fbool(fs, "apply") {
		// re-validate after save before applying
		if err := cx.cfg.Validate(); err != nil {
			fmt.Fprintf(os.Stderr, "ip-watch: saved %q but config still invalid (%v); not applying — fix it and run 'ip-watch apply'\n", t.ID, err)
			return nil
		}
		res := applier.New(cx.cfg, false).Apply(context.Background(), t, true)
		printJSON([]applier.Result{res})
		if !res.OK {
			return errExitSilent
		}
	}
	return nil
}

func runRmTarget(c *command, cx *cmdCtx, args []string) error {
	fs := c.flags()
	// <id> any position
	id, flags := firstPositional(args)
	if err := fs.Parse(flags); err != nil {
		return err
	}
	if id == "" {
		return fmt.Errorf("usage: ip-watch rm <id> [-uninstall=false]")
	}
	t, ok := cx.cfg.Target(id)
	if !ok {
		return fmt.Errorf("no target %q", id)
	}
	uninstall := fbool(fs, "uninstall")
	// live action; skip on invalid cfg (-uninstall=false ok)
	if uninstall && !cx.valid {
		return fmt.Errorf("config invalid; refusing to uninstall live rules for %q — "+
			"fix the config and retry, or pass -uninstall=false to delete the config entry only", id)
	}
	if uninstall {
		res := applier.New(cx.cfg, false).Remove(context.Background(), t)
		printJSON([]applier.Result{res})
		if !res.OK {
			return fmt.Errorf("uninstall failed; target kept (use -uninstall=false to delete config anyway)")
		}
	}
	if err := applier.GuardConfig(cx.cfg.StateDir, cx.cfg.LockUnsafe, func() error {
		cx.cfg.RemoveTarget(id)
		return cx.cfg.Save(cx.cfgPath)
	}); err != nil {
		return err
	}
	fmt.Printf("deleted target %q\n", id)
	return nil
}

func runApply(c *command, cx *cmdCtx, args []string) error {
	fs := c.flags()
	if err := fs.Parse(args); err != nil {
		return err
	}
	app := applier.New(cx.cfg, fbool(fs, "dry"))
	force := !fbool(fs, "skip-unchanged")
	ctx := context.Background()
	targetID := fstr(fs, "target")
	if targetID == "" {
		return emitResults(app.ApplyAll(ctx, force))
	}
	t, ok := cx.cfg.Target(targetID)
	if !ok {
		return fmt.Errorf("no target %q", targetID)
	}
	return emitResults([]applier.Result{app.Apply(ctx, t, force)})
}

func runRemove(c *command, cx *cmdCtx, args []string) error {
	id := ""
	if len(args) > 0 {
		id = args[0]
	}
	app := applier.New(cx.cfg, false)
	ctx := context.Background()
	var results []applier.Result
	for _, t := range cx.cfg.Targets {
		if id != "" && t.ID != id {
			continue
		}
		results = append(results, app.Remove(ctx, t))
	}
	if id != "" && len(results) == 0 {
		return fmt.Errorf("no target %q", id)
	}
	return emitResults(results)
}

func runStatus(c *command, cx *cmdCtx, args []string) error {
	if len(cx.cfg.Targets) == 0 {
		fmt.Println("no targets configured")
		return nil
	}
	st, _ := state.Load(cx.cfg.StateDir)
	hist, _ := history.Load(cx.cfg.StateDir)
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tENABLED\tENGINE\tMODE\tLAST APPLIED\tHASH\tAPPLIES\tCHANGES\tFAILURES")
	for _, t := range cx.cfg.Targets {
		last, hash := targetState(st, t.ID)
		var ct history.Counter
		if hist != nil {
			ct = hist.Counters[t.ID]
		}
		fmt.Fprintf(tw, "%s\t%v\t%s\t%s\t%s\t%s\t%d\t%d\t%d\n",
			t.ID, t.Enabled, t.Engine, t.Mode, last, hash, ct.Applies, ct.Changes, ct.Failures)
	}
	return tw.Flush()
}

func runHistory(c *command, cx *cmdCtx, args []string) error {
	fs := c.flags()
	if err := fs.Parse(args); err != nil {
		return err
	}
	store, err := history.Load(cx.cfg.StateDir)
	if err != nil {
		return fmt.Errorf("loading history: %w", err)
	}
	if fbool(fs, "json") {
		printJSON(map[string]any{"recent": store.Recent, "counters": store.Counters})
		return nil
	}
	if len(store.Recent) == 0 {
		fmt.Println("no history yet")
		return nil
	}
	n := int(fint(fs, "n"))
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "WHEN\tTARGET\tENGINE\tOK\tCHANGED\tRANGES\tMESSAGE")
	// newest first, cap n
	shown := 0
	for i := len(store.Recent) - 1; i >= 0 && shown < n; i-- {
		e := store.Recent[i]
		fmt.Fprintf(tw, "%s\t%s\t%s\t%v\t%v\t%d\t%s\n",
			e.When.Format(time.RFC3339), e.TargetID, e.Engine, e.OK, e.Changed, e.Ranges, truncate(e.Message, 60))
		shown++
	}
	return tw.Flush()
}

func runMetrics(c *command, cx *cmdCtx, args []string) error {
	store, err := history.Load(cx.cfg.StateDir)
	if err != nil {
		return fmt.Errorf("loading history: %w", err)
	}
	fmt.Print(web.RenderMetrics(store, version))
	return nil
}

func runSettings(c *command, cx *cmdCtx, args []string) error {
	fs := c.flags()
	if err := fs.Parse(args); err != nil {
		return err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	changed := false
	if fbool(fs, "clear") {
		cx.cfg.Notify = config.NotifyOpts{}
		changed = true
	}
	if set["webhook"] {
		wh := fstr(fs, "webhook")
		if wh != "" {
			if err := notify.ValidateWebhook(wh); err != nil {
				return fmt.Errorf("invalid webhook: %w", err)
			}
		}
		cx.cfg.Notify.Webhook = wh
		changed = true
	}
	if set["always"] {
		cx.cfg.Notify.Always = fbool(fs, "always")
		changed = true
	}
	if changed {
		if err := applier.GuardConfig(cx.cfg.StateDir, cx.cfg.LockUnsafe, func() error {
			return cx.cfg.Save(cx.cfgPath)
		}); err != nil {
			return err
		}
		fmt.Println("notification settings saved")
	}
	wh := cx.cfg.Notify.Webhook
	if wh == "" {
		wh = "(none)"
	}
	fmt.Printf("webhook: %s\nalways:  %v\n", wh, cx.cfg.Notify.Always)
	return nil
}

func runNotifyTest(c *command, cx *cmdCtx, args []string) error {
	if cx.cfg.Notify.Webhook == "" {
		return fmt.Errorf("no webhook configured (set one with 'ip-watch settings -webhook <url>')")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := notify.Post(ctx, cx.cfg.Notify.Webhook, "ip-watch test notification ✅", nil); err != nil {
		return fmt.Errorf("sending test notification: %w", err)
	}
	fmt.Println("test notification sent")
	return nil
}

func runDockerLs(c *command, cx *cmdCtx, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cands, err := docker.Discover(ctx, "")
	if err != nil {
		return fmt.Errorf("docker discovery: %w", err)
	}
	if len(cands) == 0 {
		fmt.Println("no candidate webserver containers found")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(tw, "CONTAINER\tIMAGE\tENGINE\tID")
	for _, cd := range cands {
		eng := cd.Engine
		if eng == "" {
			eng = "?"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", cd.Name, cd.Image, eng, shortID(cd.ID))
	}
	return tw.Flush()
}

// probeAddr: rewrite listen addr for local probe; unspecified -> loopback
func probeAddr(listen string) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen
	}
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func runHealthcheck(c *command, cx *cmdCtx, args []string) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://" + probeAddr(cx.cfg.Listen) + "/healthz")
	if err != nil {
		return fmt.Errorf("healthcheck: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %s", resp.Status)
	}
	fmt.Println("ok")
	return nil
}

func emitResults(results []applier.Result) error {
	printJSON(results)
	for _, r := range results {
		if !r.OK {
			return errExitSilent
		}
	}
	return nil
}

func printJSON(v any) {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func fstr(fs *flag.FlagSet, name string) string { return fs.Lookup(name).Value.String() }
func fbool(fs *flag.FlagSet, name string) bool  { return fs.Lookup(name).Value.String() == "true" }
func fint(fs *flag.FlagSet, name string) int64 {
	n, _ := strconv.ParseInt(fs.Lookup(name).Value.String(), 10, 64)
	return n
}

// firstPositional: first non-flag + rest
func firstPositional(args []string) (pos string, rest []string) {
	for i, a := range args {
		if !strings.HasPrefix(a, "-") {
			rest = append(rest, args[:i]...)
			rest = append(rest, args[i+1:]...)
			return a, rest
		}
	}
	return "", args
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseInts(s string) ([]int, error) {
	var out []int
	for _, p := range splitComma(s) {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("invalid number %q", p)
		}
		out = append(out, n)
	}
	return out, nil
}

func targetState(st *state.Store, id string) (lastApplied, hash string) {
	lastApplied, hash = "-", "-"
	if st == nil {
		return lastApplied, hash
	}
	entry, ok := st.Get(id)
	if !ok {
		return lastApplied, hash
	}
	if !entry.AppliedAt.IsZero() {
		lastApplied = entry.AppliedAt.Format(time.RFC3339)
	}
	if entry.Hash != "" {
		hash = entry.Hash
	}
	return lastApplied, hash
}

func transportLabel(t config.Target) string {
	switch t.Transport {
	case "docker":
		return "docker:" + t.Docker.Container
	case "":
		return "local"
	default:
		return t.Transport
	}
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > n {
		return s[:n-1] + "…"
	}
	return s
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func defaultConfigPath() string {
	if p := os.Getenv("IPWATCH_CONFIG"); p != "" {
		return p
	}
	return "/etc/ip-watch/config.json"
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "ip-watch: "+format+"\n", args...)
	os.Exit(1)
}
