# scudo — website

Source of https://mtorromeo.github.io/scudo, published by GitHub Pages from the `docs/`
folder of this branch.

- `docs/index.html` — the landing page, written by hand.
- `book/` — the documentation, an [mdbook](https://rust-lang.github.io/mdBook/) whose
  output goes to `docs/docs/`.

Rebuild the documentation after editing `book/src/` and commit the output with it:

```
mdbook build book
```

Preview locally with `mdbook serve book`, or serve the whole site under its real prefix:

```
mkdir -p /tmp/site && ln -sfn "$PWD/docs" /tmp/site/scudo
python -m http.server -d /tmp/site    # http://localhost:8000/scudo/
```
