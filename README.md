# Portfolio HTML

Public portfolio and profile pages, served by GitHub Pages.

- [Open portfolio](https://ssj9921.github.io/portfolio-html/)
- [Projects](https://ssj9921.github.io/portfolio-html/components/projects/v1.0.0/index.html)
- [용사의 쉐프 · Project](https://ssj9921.github.io/portfolio-html/components/heros-chef-project/v1.0.2/index.html)
- [Profile](https://ssj9921.github.io/portfolio-html/components/profile/v1.0.2/index.html)

The index provides an overview and links to separate Projects and Profile pages. Projects uses a responsive card list, with introduction slots reserved for the author. Project pages follow five sections: idea, what was made, environment (personal role and AI use), deliverable, and comments. The current project keeps comments reserved for the author. Six existing design components remain available and unchanged. New Project and Profile pages use the same immutable, versioned route convention. The catalog records the SHA256 of every published HTML page, separately from the source-copy hash.

Personal and career details in Profile are limited to the owner-approved name, IT-related work history, education, qualifications and award. Expected education is labeled as expected. No personal contact data or raw supporting documents are published. Project submission results, historical checks and AI contribution are described within their verified scope. Primary navigation stays within this site; the approved Google Drive submission link is retained.

Only the docs/ directory is published by GitHub Pages from main. The publisher checks the entire public export and its HTML, and the local pre-push hook checks it again before upload. Security regression tests must pass before committing.

The first-party pages use no JavaScript, external libraries, analytics or remote assets. An explicitly approved, route-scoped YouTube embed is supported as the sole external-player exception. See [security policy](SECURITY.md). Private work records and new unapproved career statements are not part of this repository.

Before uploading, run:

```text
python tools/check_public.py --history
python -m unittest discover -s tests -v
```

Set Git's local core.hooksPath to .githooks to run the export check before pushing. A working Python 3 interpreter is required. On Windows, PORTFOLIO_PYTHON can point to the existing Python executable. Local hooks can be bypassed, so repository administrators must also follow this policy for direct web edits.

The current GitHub login lacks workflow scope, so no Actions deployment gate was uploaded. Pages uses ordinary branch publication after local checks. Do not describe this as server-enforced CI security.

The pre-push check scans outgoing Git commits as well as the working tree, so deleting a secret before pushing does not silently publish it in an earlier commit.

Keep unfinished authoring, private evidence and the approval manifest in a separate local workspace outside this repository. No second repository is required. For a new component, register its ID and version in that locally retained manifest, review its public contents, export it through the approved publisher, and push only the reviewed, completed export here. Put the GitHub Pages URL in Notion as an ordinary link. Root index is current; versioned components are never overwritten.

## Scoped YouTube support

policy.json reserves components/varco-project/v1.0.0/index.html for the approved CityOfRubble video, QewprwQ5BGc. This support change does not publish that component or alter any existing HTML page. The new component must be separately reviewed, added to the catalog, and tested before publication.

The checker derives a page-specific CSP from that exact route and exact youtube-nocookie.com/embed URL. Every other page keeps frame-src 'none'. The iframe must use the fixed reviewed attributes in tools/check_public.py, including a title, lazy loading, restricted permissions, sandbox, and strict-origin-when-cross-origin referrer policy. It cannot use autoplay, URL parameters, srcdoc, event handlers, or additional attributes. An ordinary approved YouTube watch link is required beside the player. The page-level no-referrer policy remains in place for ordinary navigation.

Privacy-enhanced mode does not make the remote player an offline or first-party resource. YouTube runs its own code and can contact its services within the cross-origin frame. The checker verifies the permitted markup and CSP; it cannot establish video availability or successful playback. Verify the actual HTTPS embed page in a browser after publication.
