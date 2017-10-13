package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"

	"github.com/sroberts/cacador/aux"
)

var cacadorversion = "0.0.1"

// Hashes are all the common hash types
type Hashes struct {
	Md5s    []string `json:"md5s"`
	Sha1s   []string `json:"sha1s"`
	Sha256s []string `json:"sha256s"`
	Sha512s []string `json:"sha512s"`
	Ssdeeps []string `json:"ssdeeps"`
}

// Networks is a struct of network IOCs
type Networks struct {
	Domains []string `json:"domains"`
	Emails  []string `json:"emails"`
	Ipv4s   []string `json:"ipv4s"`
	Ipv6s   []string `json:"ipv6s"`
	Urls    []string `json:"urls"`
}

// Files is a struct representing File based IOCs
type Files struct {
	Docs    []string `json:"docs"`
	Exes    []string `json:"exes"`
	Flashes []string `json:"flashes"`
	Imgs    []string `json:"imgs"`
	Macs    []string `json:"macs"`
	Webs    []string `json:"webs"`
	Zips    []string `json:"zips"`
}

// Utilities is a struct of Utility strings
type Utilities struct {
	Cves []string `json:"cves"`
}

// Cacadordata represents the JSON output for cacador
type Cacadordata struct {
	Hashes    Hashes    `json:"hashes"`
	Networks  Networks  `json:"Networks"`
	Files     Files     `json:"files"`
	Utilities Utilities `json:"Utilities"`
	Comments  string    `json:"comments"`
	Tags      []string  `json:"tags"`
	Time      string    `json:"time"`
}

// GetHashStrings takes a string and returns a struct of hashes
func GetHashStrings(data string) Hashes {

	h := Hashes{}

	h.Md5s = aux.Dedup(aux.HashRegexs["md5"].FindAllString(data, -1))
	h.Sha1s = aux.Dedup(aux.HashRegexs["sha1"].FindAllString(data, -1))
	h.Sha256s = aux.Dedup(aux.HashRegexs["sha256"].FindAllString(data, -1))
	h.Sha512s = aux.Dedup(aux.HashRegexs["sha512"].FindAllString(data, -1))
	h.Ssdeeps = aux.Dedup(aux.HashRegexs["ssdeep"].FindAllString(data, -1))

	return h
}

// GetNetworkstrings takes a string and returns network based IOCs
func GetNetworkstrings(data string) Networks {

	n := Networks{}

	n.Domains = aux.Dedup(aux.CleanDomains(aux.NetworkRegexs["domain"].FindAllString(data, -1)))
	n.Emails = aux.Dedup(aux.NetworkRegexs["email"].FindAllString(data, -1))
	n.Ipv4s = aux.Dedup(aux.CleanIpv4(aux.NetworkRegexs["ipv4"].FindAllString(data, -1)))
	n.Ipv6s = aux.Dedup(aux.NetworkRegexs["ipv6"].FindAllString(data, -1))
	n.Urls = aux.Dedup(aux.CleanUrls(aux.NetworkRegexs["url"].FindAllString(data, -1)))

	return n
}

// GetFilenameStrings takes a string and returns a struct of file IOCs
func GetFilenameStrings(data string) Files {

	f := Files{}

	f.Docs = aux.Dedup(aux.FileRegexs["doc"].FindAllString(data, -1))
	f.Exes = aux.Dedup(aux.FileRegexs["exe"].FindAllString(data, -1))
	f.Flashes = aux.Dedup(aux.FileRegexs["flash"].FindAllString(data, -1))
	f.Imgs = aux.Dedup(aux.FileRegexs["img"].FindAllString(data, -1))
	f.Macs = aux.Dedup(aux.FileRegexs["mac"].FindAllString(data, -1))
	f.Webs = aux.Dedup(aux.FileRegexs["web"].FindAllString(data, -1))
	f.Zips = aux.Dedup(aux.FileRegexs["zip"].FindAllString(data, -1))

	return f
}

// GetUtilityStrings takes a string and returns utility strings
func GetUtilityStrings(data string) Utilities {

	u := Utilities{}

	u.Cves = aux.Dedup(aux.UtilityRegexs["cve"].FindAllString(data, -1))

	return u
}

func main() {

	comments := flag.String("comment", "", "Adds a note to the export.")
	tags := flag.String("tags", "", "Adds a list of tags to the export (comma separated).")
	version := flag.Bool("version", false, "Returns the current version of Cacador.")
	flag.Parse()

	if *version {
		fmt.Println("cacador version " + cacadorversion)
		os.Exit(0)
	}

	tagslist := strings.Split(*tags, ",")

	// Get Data from STDIN
	bytes, _ := ioutil.ReadAll(os.Stdin)
	data := string(bytes)

	c := Cacadordata{}

	c.Hashes = GetHashStrings(data)
	c.Networks = GetNetworkstrings(data)
	c.Files = GetFilenameStrings(data)
	c.Utilities = GetUtilityStrings(data)
	c.Comments = *comments
	c.Tags = tagslist
	c.Time = time.Now().String()

	b, _ := json.MarshalIndent(c," "," ")

	fmt.Println(string(b))

	os.Exit(0)
}
