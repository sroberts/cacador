# cacador

[![codebeat badge](https://codebeat.co/badges/5c1a1d71-4d26-4833-84ac-a1be85bc3bbc)](https://codebeat.co/projects/github-com-sroberts-cacador)

Cacador (Portugese for hunter) is tool for extracting common [indicators of compromise](https://en.wikipedia.org/wiki/Indicator_of_compromise) from a block of text.

## Compiling & Running

- Install golang
- Compile with `go build cacador.go`
- Run with `./cacador`. It accepts text from stdin and writes a JSON blob of IOCs to stdout. For example `cat text.txt | ./cacador | import` where text is some IOC rich text and import pushes your new IOCs into your threat management system.

## Why?

There are other tools for doing indicator extraction, but what's nice about cacador is you can compile it and put it in your path and use it for Unix style workflows with pipes and things.
