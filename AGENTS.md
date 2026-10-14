# Public HTML repository

This repository is public, including every Git commit. Publish only reviewed HTML, public policy, security tools and deployment configuration. Never copy the local authoring workspace, any private Git history, research files, drafts, internal references, personal career records or credentials here.

All future generated portfolio HTML is routed here after the security checks. Use this single public repository for reviewed, completed exports. Unfinished authoring, private evidence and the approval manifest stay in a separate local workspace outside this repository. Use GitHub Pages URLs in Notion as ordinary links; do not attach raw HTML files.

The owner authorized first-party JavaScript on 2026-10-14. Allow only reviewed inline code whose SHA256 hashes are registered for its exact immutable route in policy.json. Never enable unsafe-inline or unsafe-eval for scripts. External libraries, remote assets, forms, analytics, browser storage and network connections remain disabled. Preserve the separately approved route-scoped privacy-enhanced YouTube player. Use only reviewed HTTPS navigation links. New career, personal role and outcome statements still require the owner's approval of the wording.

Run python tools/check_public.py and python -m unittest discover -s tests before every commit and upload. Stop if either check fails. Versioned component routes are immutable; a source or policy change requires a new component version. Root index.html is the current navigation page.

The owner approved three Chef screenshots on 2026-10-14. Only immutable PNG/JPEG assets registered by exact hash, dimensions and media type in approved_image_assets may be exported. approved_page_images limits their use to reviewed component routes. Those pages use img-src 'self'; every image source and attribute is checked against the exact asset list. Other pages retain img-src 'none'. Strip private metadata in public copies without changing pixels; preserve originals outside this repository. Do not generalize this exception to remote assets, SVG, data URLs or other binaries.

The owner also approved three City Of Rubble screenshots and the Projects card redesign on 2026-10-14. Projects v1.6.0 and VARCO v1.1.0 receive only their exact assigned images and the reviewed hash of the image fallback script. Stock uses a title panel without an image. Preserve earlier immutable versions and the route-scoped YouTube permission.

Use the existing repository and main branch, publishing the docs/ directory through GitHub Pages. Run checks before any push; no CI deployment gate is installed because the current login lacks workflow scope. Do not change visibility, attach private data sources, disable the local security gate or weaken the policy. Never print tokens or store them in source, logs or Git.
