package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"time"
)

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

	h.Md5s = dedup(md5Regex.FindAllString(data, -1))
	h.Sha1s = dedup(sha1Regex.FindAllString(data, -1))
	h.Sha256s = dedup(sha256Regex.FindAllString(data, -1))
	h.Sha512s = dedup(sha512Regex.FindAllString(data, -1))
	h.Ssdeeps = dedup(ssdeepRegex.FindAllString(data, -1))

	return h
}

func getNetworkStrings(data string) networks {

	n := networks{}

	n.Domains = dedup(cleanDomains(domainRegex.FindAllString(data, -1)))
	n.Emails = dedup(emailRegex.FindAllString(data, -1))
	n.Ipv4s = dedup(cleanIpv4(ipv4Regex.FindAllString(data, -1)))
	n.Ipv6s = dedup(ipv6Regex.FindAllString(data, -1))
	n.Urls = dedup(cleanUrls(urlRegex.FindAllString(data, -1)))

	return n
}

func getFilenameStrings(data string) files {

	f := files{}

	f.Docs = dedup(docRegex.FindAllString(data, -1))
	f.Exes = dedup(exeRegex.FindAllString(data, -1))
	f.Flashes = dedup(flashRegex.FindAllString(data, -1))
	f.Imgs = dedup(imgRegex.FindAllString(data, -1))
	f.Macs = dedup(macRegex.FindAllString(data, -1))
	f.Webs = dedup(webRegex.FindAllString(data, -1))
	f.Zips = dedup(zipRegexs.FindAllString(data, -1))

	return f
}

func getUtilityStrings(data string) utilities {

	u := utilities{}

	u.Cves = dedup(cveRegex.FindAllString(data, -1))

	return u
}

func main() {

	comments := flag.String("comment", "Automatically imported.", "Adds a note to the export.")
	tags := flag.String("tags", "", "Adds a list of tags to the export (comma seperated).")
	flag.Parse()

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
}
