# Portfolio HTML

Public HTML pages for the Notion portfolio, served by GitHub Pages.

- [Open portfolio](https://ssj9921.github.io/portfolio-html/)
- [Public Notion portfolio](https://extreme-filament-0b2.notion.site/Portfolio-Selected-Work-3f863d9201b28121a1d1d1258d666611)

The index contains published project links and six reusable HTML design pages. Each component has a versioned URL. The catalog records the SHA256 of every published HTML page.

Only the docs/ directory is published by GitHub Pages from main. The publisher checks the entire public export and its HTML, and the local pre-push hook checks it again before upload. Security regression tests must pass before committing.

No JavaScript, external libraries, analytics or remote assets are used. See [security policy](SECURITY.md). Private work records and new unapproved career statements are not part of this repository.

Before uploading, run:

```text
python tools/check_public.py --history
python -m unittest discover -s tests -v
```

Set Git's local core.hooksPath to .githooks to run the export check before pushing. A working Python 3 interpreter is required. On Windows, PORTFOLIO_PYTHON can point to the existing Python executable. Local hooks can be bypassed, so repository administrators must also follow this policy for direct web edits.

The current GitHub login lacks workflow scope, so no Actions deployment gate was uploaded. Pages uses ordinary branch publication after local checks. Do not describe this as server-enforced CI security.

The pre-push check scans outgoing Git commits as well as the working tree, so deleting a secret before pushing does not silently publish it in an earlier commit.

For a new component, register its ID and version in the private source manifest, review its public contents, export it through the approved publisher, and push the checked export here. Put the GitHub Pages URL in Notion as an ordinary link. Root index is current; versioned components are never overwritten.
