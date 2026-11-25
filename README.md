# Links — Data Branch

This branch holds **only** the keep-alive link list (`links.txt`) plus a tiny
trigger workflow. It is intentionally an orphan branch (no shared history with
`main`) so that frequent, non-code data updates never pollute the code history.

Every push to this branch that changes `links.txt` automatically dispatches the
real keep-alive workflow (`daily_check.yml`) on `main` — see
`.github/workflows/trigger-keepalive.yml`.

## Adding / removing links

Edit `links.txt` directly — the GitHub web UI "pencil" editor works on this
branch — and commit. The keep-alive run starts within seconds.

Or locally:

```bash
git fetch origin
git switch links
# edit links.txt
git commit -am "add backup links"
git push origin links
```

The scheduled runs on `main` (3x daily) always read the latest `links.txt`
from this branch, so even a plain edit without the instant trigger is picked
up by the next scheduled run.

> AI生成
