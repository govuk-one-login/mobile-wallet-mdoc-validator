#!/usr/bin/env bash

set -e

# Bootstrap a package on npm as v0.0.0 so the package exists before OIDC /
# trusted-publisher config is possible. Only a bare package.json is published,
# no WIP code. npm publish prompts for browser login (2FA), so no token needed.

SCOPE=govuk-one-login
NAME=mobile-wallet-mdoc-validator

echo "Run this from the repo root, ideally via 'npm run publish-v0-to-npm'."

mkdir -p publish-temp/$NAME
cd publish-temp/$NAME

echo "{
  \"name\": \"@$SCOPE/$NAME\",
  \"version\": \"0.0.0\"
}
" > package.json

npm publish --access public || (cd ../.. && rm -r publish-temp)

cd ../..

rm -r publish-temp

echo "Package published. Now go set up the trusted publisher (OIDC). 👋"

open "https://www.npmjs.com/package/@$SCOPE/$NAME/access"
