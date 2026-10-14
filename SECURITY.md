# HTML generation and publication policy

This repository and its complete commit history are public. Client-side hiding, CSS, CSP and a private authoring source do not make uploaded data private.

## Allowed content

- Reviewed public copy, reusable design templates and approved HTTPS navigation links.
- Standalone UTF-8 HTML with CSS, viewport metadata, no-referrer and the required CSP before content.
- The approved public text files and versioned routes accepted by the export checker.

## Prohibited content and features

- Secrets, access tokens, API keys, passwords, signed attachment links or embedded credentials.
- Internal Notion links, private source documents, company materials, unpublished career details, unapproved personal contact information, local paths or local development addresses.
- First-party JavaScript, event handlers, execution URLs, external libraries, external CSS, remote images/fonts, arbitrary iframe/embed, forms, tracking, browser storage and server-dependent features. The sole iframe exception is the reviewed YouTube player described below.
- Symbolic links, binary attachments, unregistered files, unlisted HTML or catalog hashes that do not match.
- New personal roles, career or outcome claims without owner approval of their concrete wording.

Do not copy a private repository into this one or reuse its Git history. Export only the reviewed files. Treat all comments, hidden elements and metadata as public content.

The pre-push gate also checks unpublished Git commits, including files and values deleted from the current tree. A failed check stops the upload; rewriting local unpublished history must not be confused with erasing information already made public.

## Checks and updates

Generation → source review → checked export → regression tests → local pre-push check → branch upload → Pages deployment → verify the HTTPS page → attach its URL in Notion.

Current publication uses main/docs. An Actions gate could not be uploaded because the GitHub login lacks workflow scope. Local checks and hooks are enforced by the configured publisher, but administrators can bypass hooks or edit through GitHub; those paths must follow the same review policy. No server-enforced CI gate is claimed.

The checker is a useful gate, not proof that all sensitive information can be detected automatically. Human review of new facts and company material remains required. New external destinations need explicit review before entering policy.json.

Component versions are immutable. If HTML or security metadata changes, create a new version rather than overwrite a versioned URL. Keep the existing source hash and deployed hash distinct.

## Browser policy and hosting limits

The first-party page CSP blocks scripts, resource loading, connections and form submissions. Only inline CSS is allowed. Frames remain blocked unless that exact versioned route has an approved YouTube exception below. Navigation uses approved HTTPS URLs and new-window links use noopener and noreferrer. The page-level no-referrer metadata prevents sending the page URL through ordinary navigation.

The CSP is delivered through HTML metadata. It does not implement HTTP-only directives such as frame-ancestors, and it does not restrict who can read this public source. No claim is made that GitHub Pages provides custom response-header enforcement. Use ordinary Notion links rather than relying on embedding behavior.

If a sensitive value is discovered, stop publication, remove it from source and history as appropriate, and revoke any leaked credential. Deleting the visible HTML alone cannot retract copies already made.

References: [GitHub Pages custom workflows](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages), [MDN CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP).

## Approved YouTube player exception

Only policy.json's approved_youtube_embeds mapping may authorize a frame. Each entry maps one immutable component route to exact HTTPS URLs matching https://www.youtube-nocookie.com/embed/VIDEO_ID. No other host, wildcard, path, query parameter, playlist, or unregistered page is permitted. Adding another video or changing the allowed route requires explicit review. A reserved route is not evidence that a page is published or its content is approved.

The current approval is components/varco-project/v1.0.0/index.html with video QewprwQ5BGc and its ordinary watch URL. Existing component HTML and CSP remain unchanged. Only the approved page may replace frame-src 'none' with its exact approved URL; all other CSP directives remain identical. The gate checks both the working tree and outgoing Git history using the page's actual route.

The iframe must be empty, explicitly closed, and use the fixed attributes in IFRAME_ATTRIBUTES, plus a nonempty title, its exact approved src, and boolean allowfullscreen. The sandbox permits only scripts, same-origin behavior inside the cross-origin player, and presentation. The feature policy explicitly denies autoplay, and the source URL accepts no parameters. No srcdoc, event handlers, arbitrary attributes, first-party script, or object/embed element is allowed. A normal approved watch-on-YouTube link is mandatory as a fallback.

The iframe alone uses strict-origin-when-cross-origin, sending only the public site's origin to HTTPS YouTube as required for player identification. It does not change the no-referrer policy for the rest of the page. The cross-origin player loads and executes YouTube-controlled resources; the first-party page's script/resource restrictions do not sandbox all of YouTube's network activity or promise zero cookies, storage, ads, or tracking. Privacy-enhanced mode limits personalization, not all third-party communication. The standard YouTube embedded-player terms apply.

After publishing an embed page, check frame loading, CSP, no autoplay, the fallback link, layout, and actual playback separately. A loaded iframe or buffering indicator is not proof that video playback succeeded.

References: [YouTube embedding, privacy-enhanced mode and referrer requirements](https://support.google.com/youtube/answer/171780?hl=en), [YouTube player parameters](https://developers.google.com/youtube/player_parameters).
