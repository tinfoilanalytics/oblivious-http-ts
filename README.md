# oblivious-http

A TypeScript [RFC 9458 Oblivious HTTP (OHTTP)](https://www.rfc-editor.org/rfc/rfc9458.html) implementation.

This was originally forked from https://github.com/chris-wood/ohttp-js.

To install dependencies:

```bash
bun install
```

To run:

```bash
bun run index.ts
```

To build:

```bash
bun run build
```

To publish:

First, update the version in `package.json`.

Then, commit the version change and create and push a new tag:

```bash
git add package.json
git commit -m "Release vX.Y.Z"
git tag vX.Y.Z # where X.Y.Z matches the version in package.json
git push origin main --tags
```

This will trigger the GitHub Actions workflow to automatically build and publish the package to `npm`.

## Contributing

We welcome contributions from everyone! Feel free to open issues, submit pull requests, or engage in discussions to help improve this project.
