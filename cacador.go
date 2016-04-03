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

type hashes struct {
	Md5s    []string `json:"md5s"`
	Sha1s   []string `json:"sha1s"`
	Sha256s []string `json:"sha256s"`
	Sha512s []string `json:"sha512s"`
	Ssdeeps []string `json:"ssdeeps"`
}

type networks struct {
	Domains []string `json:"domains"`
	Emails  []string `json:"emails"`
	Ipv4s   []string `json:"ipv4s"`
	Ipv6s   []string `json:"ipv6s"`
	Urls    []string `json:"urls"`
}

type files struct {
	Docs    []string `json:"docs"`
	Exes    []string `json:"exes"`
	Flashes []string `json:"flashes"`
	Imgs    []string `json:"imgs"`
	Macs    []string `json:"macs"`
	Webs    []string `json:"webs"`
	Zips    []string `json:"zips"`
}

type utilities struct {
	Cves []string `json:"md5s"`
}

type cacadordata struct {
	Hashes    hashes    `json:"hashes"`
	Networks  networks  `json:"networks"`
	Files     files     `json:"files"`
	Utilities utilities `json:"utilities"`
	Comments  string    `json:"comments"`
	Tags      []string  `json:"tags"`
	Time      string    `json:"time"`
}

func getHashStrings(data string) hashes {

	h := hashes{}

	h.Md5s = aux.Dedup(aux.HashRegexs["md5"].FindAllString(data, -1))
	h.Sha1s = aux.Dedup(aux.HashRegexs["sha1"].FindAllString(data, -1))
	h.Sha256s = aux.Dedup(aux.HashRegexs["sha256"].FindAllString(data, -1))
	h.Sha512s = aux.Dedup(aux.HashRegexs["sha512"].FindAllString(data, -1))
	h.Ssdeeps = aux.Dedup(aux.HashRegexs["ssdeep"].FindAllString(data, -1))

	return h
}

func getNetworkStrings(data string) networks {

	n := networks{}

	n.Domains = aux.Dedup(aux.CleanDomains(aux.NetworkRegexs["domain"].FindAllString(data, -1)))
	n.Emails = aux.Dedup(aux.NetworkRegexs["email"].FindAllString(data, -1))
	n.Ipv4s = aux.Dedup(aux.CleanIpv4(aux.NetworkRegexs["ipv4"].FindAllString(data, -1)))
	n.Ipv6s = aux.Dedup(aux.NetworkRegexs["ipv6"].FindAllString(data, -1))
	n.Urls = aux.Dedup(aux.CleanUrls(aux.NetworkRegexs["url"].FindAllString(data, -1)))

	return n
}

func getFilenameStrings(data string) files {

	f := files{}

	f.Docs = aux.Dedup(aux.FileRegexs["doc"].FindAllString(data, -1))
	f.Exes = aux.Dedup(aux.FileRegexs["exe"].FindAllString(data, -1))
	f.Flashes = aux.Dedup(aux.FileRegexs["flash"].FindAllString(data, -1))
	f.Imgs = aux.Dedup(aux.FileRegexs["img"].FindAllString(data, -1))
	f.Macs = aux.Dedup(aux.FileRegexs["mac"].FindAllString(data, -1))
	f.Webs = aux.Dedup(aux.FileRegexs["web"].FindAllString(data, -1))
	f.Zips = aux.Dedup(aux.FileRegexs["zip"].FindAllString(data, -1))

	return f
}

func getUtilityStrings(data string) utilities {

	u := utilities{}

	u.Cves = aux.Dedup(aux.UtilityRegexs["cve"].FindAllString(data, -1))

	return u
}

func main() {

	comments := flag.String("comment", "Automatically imported.", "Adds a note to the export.")
	tags := flag.String("tags", "", "Adds a list of tags to the export (comma seperated).")
	version := flag.Bool("version", false, "Returns the current version of Cacador.")
	flag.Parse()

	if *version {
		fmt.Println(cacadorversion)
		os.Exit(0)
	}

	tagslist := strings.Split(*tags, ",")

	// Get Data from STDIN
	bytes, _ := ioutil.ReadAll(os.Stdin)
	data := string(bytes)

	c := cacadordata{}

	c.Hashes = getHashStrings(data)
	c.Networks = getNetworkStrings(data)
	c.Files = getFilenameStrings(data)
	c.Utilities = getUtilityStrings(data)
	c.Comments = *comments
	c.Tags = tagslist
	c.Time = time.Now().String()

	b, _ := json.Marshal(c)

	fmt.Println(string(b))

	os.Exit(0)
}
