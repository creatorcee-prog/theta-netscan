# Theta NetScan v0.3

**Network Intelligence & Field Diagnostics Platform**

Vendor-neutral network discovery and diagnostic application. Stage 1 foundation + first increment: relationship-driven topology, evidence/confidence model, discovery capability panel, and validated import/export.

## Run on iPhone

After enabling GitHub Pages (Settings → Pages → Deploy from branch `main` / root):

**https://creatorcee-prog.github.io/theta-netscan/**

Open in Safari → Share → Add to Home Screen.

## Local development

```bash
cd theta-netscan
python3 -m http.server 8080
```

## Architecture

```
src/js/
  models.js        — Normalized entities, confidence, categories
  storage.js       — IndexedDB + localStorage session isolation
  import.js        — CSV/JSON parse + validation (no silent drops)
  capabilities.js  — Browser vs agent capability matrix
  topology.js      — Dynamic map from Relationship records only
  app.js           — UI controller, views, forms
src/css/           — Dark technical field-tool theme
```

## Key design rules enforced

1. Topology edges come only from `Relationship` records with confidence levels.
2. Metrics that cannot be measured show “Not measured” / “Backend required”.
3. Failed or unavailable adapters never invent data.
4. Sessions are isolated; client networks never mix.
5. Import always reports validation errors and warnings.
