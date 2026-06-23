package main

import (
	"fmt"
	"html"
	"os"
	"strings"
)

// writeHTML produces a self-contained local report file. It is written to disk
// on the user's machine only; nothing is transmitted.
func writeHTML(r *Report, path string) error {
	var b strings.Builder
	esc := html.EscapeString

	fail, warn, ok, info := r.counts()
	score := r.score()
	scoreColor := "#34d399"
	if score < 50 {
		scoreColor = "#ff6b6b"
	} else if score < 80 {
		scoreColor = "#f6c453"
	}

	b.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width,initial-scale=1">`)
	b.WriteString(`<title>Posture Report — ` + esc(r.Host.Hostname) + `</title><style>`)
	b.WriteString(`body{background:#0a0e14;color:#e8eef5;font-family:-apple-system,Segoe UI,Roboto,sans-serif;margin:0;padding:32px;line-height:1.55}`)
	b.WriteString(`.wrap{max-width:860px;margin:0 auto}h1{font-size:22px;margin:0 0 4px}.dim{color:#6b7d92;font-size:13px}`)
	b.WriteString(`.meta{font-size:13px;color:#9fb0c3;margin:14px 0}`)
	b.WriteString(`.score{font-size:26px;font-weight:800;margin:18px 0 6px}`)
	b.WriteString(`.cat{font-size:12px;letter-spacing:.1em;text-transform:uppercase;color:#6b7d92;margin:26px 0 10px;border-bottom:1px solid #1f2b3a;padding-bottom:6px}`)
	b.WriteString(`.f{border:1px solid #1f2b3a;border-left-width:3px;border-radius:10px;padding:13px 16px;margin-bottom:10px;background:#121a26}`)
	b.WriteString(`.f.fail{border-left-color:#ff6b6b}.f.warn{border-left-color:#f6c453}.f.ok{border-left-color:#34d399}.f.info{border-left-color:#3b9eff}`)
	b.WriteString(`.ft{display:flex;justify-content:space-between;gap:12px;align-items:center}.ft b{font-size:15px}`)
	b.WriteString(`.badge{font-size:11px;font-weight:700;padding:3px 9px;border-radius:100px;font-family:ui-monospace,monospace}`)
	b.WriteString(`.b-fail{background:rgba(255,107,107,.16);color:#ff6b6b}.b-warn{background:rgba(246,196,83,.16);color:#f6c453}`)
	b.WriteString(`.b-ok{background:rgba(52,211,153,.16);color:#34d399}.b-info{background:rgba(59,158,255,.16);color:#3b9eff}`)
	b.WriteString(`.d{color:#9fb0c3;font-size:13.5px;margin-top:6px}.why{color:#9fb0c3;font-size:13px;margin-top:5px}`)
	b.WriteString(`.fix{font-size:13px;margin-top:7px;background:rgba(59,158,255,.07);border:1px solid #2a3a4f;border-radius:7px;padding:8px 10px}`)
	b.WriteString(`.priv{margin-top:30px;font-size:12px;color:#6b7d92;border-top:1px solid #1f2b3a;padding-top:16px}`)
	b.WriteString(`</style></head><body><div class="wrap">`)

	b.WriteString(`<h1>` + esc(r.Tool) + `</h1>`)
	b.WriteString(`<div class="dim">` + esc(r.Version) + ` · ` + esc(r.When) + `</div>`)
	b.WriteString(`<div class="meta"><b>` + esc(r.Host.Hostname) + `</b> — ` + esc(r.Host.OSName) +
		` (` + esc(r.Host.OS) + `, ` + esc(r.Host.Arch) + `)`)
	if r.Host.Kernel != "" {
		b.WriteString(` · ` + esc(r.Host.Kernel))
	}
	b.WriteString(`</div>`)
	b.WriteString(fmt.Sprintf(`<div class="score" style="color:%s">Posture score: %d/100</div>`, scoreColor, score))
	b.WriteString(fmt.Sprintf(`<div class="dim">%d fail · %d warn · %d ok · %d info</div>`, fail, warn, ok, info))

	lastCat := ""
	for _, f := range r.Findings {
		if f.Category != lastCat {
			b.WriteString(`<div class="cat">` + esc(f.Category) + `</div>`)
			lastCat = f.Category
		}
		cls, bcls := "info", "b-info"
		switch f.Status {
		case StatusFail:
			cls, bcls = "fail", "b-fail"
		case StatusWarn:
			cls, bcls = "warn", "b-warn"
		case StatusOK:
			cls, bcls = "ok", "b-ok"
		}
		b.WriteString(`<div class="f ` + cls + `"><div class="ft"><b>` + esc(f.Title) + `</b>`)
		b.WriteString(`<span class="badge ` + bcls + `">` + f.Status.Label() + `</span></div>`)
		if f.Detail != "" {
			b.WriteString(`<div class="d">` + esc(f.Detail) + `</div>`)
		}
		if f.Why != "" {
			b.WriteString(`<div class="why"><b>Why it matters:</b> ` + esc(f.Why) + `</div>`)
		}
		if f.Fix != "" {
			b.WriteString(`<div class="fix"><b>Fix:</b> ` + esc(f.Fix) + `</div>`)
		}
		b.WriteString(`</div>`)
	}

	b.WriteString(`<div class="priv">Generated locally by ` + esc(r.Tool) +
		`. All results stay on this machine — nothing was transmitted to ByTE X Bit or anyone else. ` +
		`This is a host-only check; network posture is a separate, opt-in step.</div>`)
	b.WriteString(`</div></body></html>`)

	return os.WriteFile(path, []byte(b.String()), 0o644)
}
