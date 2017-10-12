# cacador

[![CircleCI](https://circleci.com/gh/sroberts/cacador.svg?style=svg)](https://circleci.com/gh/sroberts/cacador)
[![Go Report Card](https://goreportcard.com/badge/github.com/sroberts/cacador)](https://goreportcard.com/report/github.com/sroberts/cacador)

Cacador (Portugese for hunter) is tool for extracting common [indicators of compromise](https://en.wikipedia.org/wiki/Indicator_of_compromise) from a block of text.

## The Short Way: Downloading Cacador

The easiest way to get cacador is to [download the latest release for your platform](https://github.com/sroberts/cacador/releases). Good? Great.

## The Long Way: Compiling Cacador

- Install golang
- `go get github.com/sroberts/cacador`
- Compile with `go build`

## Running

Run with `./cacador`. It accepts text from stdin and writes a JSON blob of IOCs to stdout. For example `cat text.txt | ./cacador | import` where text is some IOC rich text and import pushes your new IOCs into your threat management system.

Cacador does recognize two command line flags:
- `-comment="Foo"` which makes it possible to leave a note as metadata.
- `-tags="Foo, bar, baz"` which adds tags.

## Generating a new release

- Install [goreleaser](https://github.com/goreleaser/goreleaser) via `go get github.com/goreleaser/goreleaser`.
- Push your branch to GitHub.
- Tag it via `git tag -a v1.0.3 -m "Release 1.0.3 - Minor bugfix edition."`
- Push the tag to GitHub via `git push origin v1.0.3`

## Why?

Other tools for doing indicator extraction are pretty awesome (like [armbues/ioc_parser](https://github.com/armbues/ioc_parser) or [sroberts/jager](https://github.com/sroberts/jager)), but what's nice about cacador is you can compile it and put it in your path and use it for Unix style workflows with [pipes and things](http://www.december.com/unix/tutor/pipesfilters.html). Also it's super fast and was a good excuse to learn [Go](http://golang.org).
