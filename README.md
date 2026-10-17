# scudo — website

Source of https://mtorromeo.github.io/scudo, published by GitHub Pages from the `docs/`
folder of this branch.

- `docs/index.html` — the landing page, written by hand.
- `docs/docs/` — the documentation, built from the mdbook in `book/` on `main`.

The documentation is not edited here. It lives on `main`, next to the code it describes, and
the release workflow builds it from each tag and commits the output to `docs/docs/`: what
`main` documents is not released until then. To preview it, run `cargo make docs-serve` on
`main`.

To serve the whole site under its real prefix:

```
mkdir -p /tmp/site && ln -sfn "$PWD/docs" /tmp/site/scudo
python -m http.server -d /tmp/site    # http://localhost:8000/scudo/
```
