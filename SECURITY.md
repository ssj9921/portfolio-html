# HTML generation and publication policy

This repository and its complete commit history are public. Client-side hiding, CSS, CSP and a private authoring source do not make uploaded data private.

## Allowed content

- Reviewed public copy, reusable design templates and approved HTTPS navigation links.
- Standalone UTF-8 HTML with CSS, viewport metadata, no-referrer and the required CSP before content.
- The approved public text files and versioned routes accepted by the export checker.

## Prohibited content and features

- Secrets, access tokens, API keys, passwords, signed attachment links or embedded credentials.
- Internal Notion links, private source documents, company materials, unpublished career details, unapproved personal contact information, local paths or local development addresses.
- JavaScript, event handlers, execution URLs, external libraries, external CSS, remote images/fonts, iframe/embed, forms, tracking, browser storage and server-dependent features.
- Symbolic links, binary attachments, unregistered files, unlisted HTML or catalog hashes that do not match.
- New personal roles, career or outcome claims without owner approval of their concrete wording.

Do not copy a private repository into this one or reuse its Git history. Export only the reviewed files. Treat all comments, hidden elements and metadata as public content.

## Checks and updates

Generation → source review → checked export → regression tests → local pre-push check → branch upload → Pages deployment → verify the HTTPS page → attach its URL in Notion.

Current publication uses main/docs. An Actions gate could not be uploaded because the GitHub login lacks workflow scope. Local checks and hooks are enforced by the configured publisher, but administrators can bypass hooks or edit through GitHub; those paths must follow the same review policy. No server-enforced CI gate is claimed.

The checker is a useful gate, not proof that all sensitive information can be detected automatically. Human review of new facts and company material remains required. New external destinations need explicit review before entering policy.json.

Component versions are immutable. If HTML or security metadata changes, create a new version rather than overwrite a versioned URL. Keep the existing source hash and deployed hash distinct.

## Browser policy and hosting limits

CSP blocks scripts, resource loading, frames, connections and form submissions. Only inline CSS is allowed. Navigation uses approved HTTPS URLs and new-window links use noopener and noreferrer. Referrer metadata prevents sending the page URL to those destinations.

The CSP is delivered through HTML metadata. It does not implement HTTP-only directives such as frame-ancestors, and it does not restrict who can read this public source. No claim is made that GitHub Pages provides custom response-header enforcement. Use ordinary Notion links rather than relying on embedding behavior.

If a sensitive value is discovered, stop publication, remove it from source and history as appropriate, and revoke any leaked credential. Deleting the visible HTML alone cannot retract copies already made.

References: [GitHub Pages custom workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages), [MDN CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP).
