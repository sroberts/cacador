package main

import (
  "fmt"
)

func printMessage (message string) (string) {
  return message
}


func main() {
  fmt.Println(printMessage("Hello World!"))
}
