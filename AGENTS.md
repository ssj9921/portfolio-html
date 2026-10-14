# Public HTML repository

This repository is public, including every Git commit. Publish only reviewed HTML, public policy, security tools and deployment configuration. Never copy the local authoring workspace, any private Git history, research files, drafts, internal references, personal career records or credentials here.

All future generated portfolio HTML is routed here after the security checks. Use this single public repository for reviewed, completed exports. Unfinished authoring, private evidence and the approval manifest stay in a separate local workspace outside this repository. Use GitHub Pages URLs in Notion as ordinary links; do not attach raw HTML files.

Keep first-party JavaScript, external libraries, remote assets, forms, analytics and browser storage disabled. The only approved exception is the route-scoped privacy-enhanced YouTube player defined in policy.json and SECURITY.md; do not broaden it to arbitrary frames or scripts. Use only reviewed HTTPS navigation links. New career, personal role and outcome statements still require the owner's approval of the wording.

Run python tools/check_public.py and python -m unittest discover -s tests before every commit and upload. Stop if either check fails. Versioned component routes are immutable; a source or policy change requires a new component version. Root index.html is the current navigation page.

Use the existing repository and main branch, publishing the docs/ directory through GitHub Pages. Run checks before any push; no CI deployment gate is installed because the current login lacks workflow scope. Do not change visibility, attach private data sources, disable the local security gate or weaken the policy. Never print tokens or store them in source, logs or Git.
