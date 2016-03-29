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

type cacadordata struct {
	Hashes   map[string][]string
	Networks map[string][]string
	Files    map[string][]string
	Utility  map[string][]string
	Comments string
	Tags     []string
	Time     string
}

func getHashStrings(data string) map[string][]string {

	h := make(map[string][]string)

	h["md5s"] = dedup(md5Regex.FindAllString(data, -1))
	h["sha1s"] = dedup(sha1Regex.FindAllString(data, -1))
	h["sha256s"] = dedup(sha256Regex.FindAllString(data, -1))
	h["sha512s"] = dedup(sha512Regex.FindAllString(data, -1))
	h["ssdeeps"] = dedup(ssdeepRegex.FindAllString(data, -1))

	return h
}

func getNetworkStrings(data string) map[string][]string {

	n := make(map[string][]string)

	n["domains"] = dedup(cleanDomains(domainRegex.FindAllString(data, -1)))
	n["emails"] = dedup(emailRegex.FindAllString(data, -1))
	n["ipv4s"] = dedup(cleanIpv4(ipv4Regex.FindAllString(data, -1)))
	n["ipv6s"] = dedup(ipv6Regex.FindAllString(data, -1))
	n["urls"] = dedup(cleanUrls(urlRegex.FindAllString(data, -1)))

	return n
}

func getFilenameStrings(data string) map[string][]string {

	f := make(map[string][]string)

	f["docs"] = dedup(docRegex.FindAllString(data, -1))
	f["exes"] = dedup(exeRegex.FindAllString(data, -1))
	f["flashes"] = dedup(flashRegex.FindAllString(data, -1))
	f["imgs"] = dedup(imgRegex.FindAllString(data, -1))
	f["macs"] = dedup(macRegex.FindAllString(data, -1))
	f["webs"] = dedup(webRegex.FindAllString(data, -1))
	f["zips"] = dedup(zipRegexs.FindAllString(data, -1))

	return f
}

func getUtilityStrings(data string) map[string][]string {

	u := make(map[string][]string)

	u["cves"] = dedup(cveRegex.FindAllString(data, -1))

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
	c.Utility = getUtilityStrings(data)
	c.Comments = *comments
	c.Tags = tagslist
	c.Time = time.Now().String()

	b, _ := json.Marshal(c)

	fmt.Println(string(b))
}
