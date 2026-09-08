# Mobile Wallet mdoc Validator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

A TypeScript library for validating mdoc (ISO 18013-5) documents for use with GOV.UK Wallet.

## Tech stack

Built with TypeScript and Node.js (v22+).

## Prerequisites

- [Node.js](https://nodejs.org/en) — we recommend managing versions with [nvm](https://github.com/nvm-sh/nvm)
- [Pre-commit](https://pre-commit.com/)

## Set up locally

### Install

```bash
nvm use
npm install
```

### Lint and format

```bash
npm run lint
npm run format
```

### Type check

```bash
npm run typecheck
```

### Build

```bash
npm run build
```

## Contributing

This project uses [pre-commit](https://pre-commit.com/) to enforce code quality and validate commit messages against [Conventional Commits](https://www.conventionalcommits.org/) standards. Non-conforming messages will be rejected.

Ensure your branch is up to date and all hooks pass before opening a pull request.

### Installing pre-commit hooks

```bash
pre-commit install --hook-type pre-commit --hook-type commit-msg
```

## Licence

[MIT License](LICENSE)
