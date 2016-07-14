#!/bin/sh

if [ -z "$1" ]; then
  echo "No pull request ID was specified."
  exit 1
fi

git fetch origin pull/${1}/head
git checkout FETCH_HEAD
npm install
npm test
npm start
