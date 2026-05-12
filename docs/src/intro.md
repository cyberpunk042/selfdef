# Introduction

This is the operator and developer manual for `selfdef`.

`selfdef` is a layered host detection, deception, and response service for
Debian 13+ / Ubuntu 24.04+. See [Architecture](./architecture.md) for the
big picture, [Threat Model](./security.md) for what the service defends
against (and how it defends itself), and the Operations chapter to install
and configure a node.

This manual is built with `mdbook`. To preview locally:

```bash
cargo install mdbook
mdbook serve docs --open
```
