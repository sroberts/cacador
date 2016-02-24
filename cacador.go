package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strings"
	"time"
)

type cacadordata struct {
	// Hashes
	Md5s    []string
	Sha1s   []string
	Sha256s []string
	Sha512s []string
	Ssdeeps []string

	// Network
	Domains []string
	Emails  []string
	Ipv4s   []string
	Ipv6s   []string
	Urls    []string

	// Files
	Docs    []string
	Exes    []string
	Flashes []string
	Imgs    []string
	Macs    []string
	Webs    []string
	Zips    []string

	// Utility
	Cves []string

	// Metadata
	Comments string
	Tags     []string
	Time     string
}

// Blaclists
var domainBlacklist = []string{"github.com", "intego.com", "fireeye.com", "trendmicro.com", "kaspersky.com", "thesafemac.com", "virusbtn.com", "symantec.com", "f-secure.com", "securelist.com", "microsoft.com", "example.com", "centralops.net", "gmail.com", "twimg.com", "twitter.com", "mandiant.com", "secureworks.com", "com.", ".plist", ".tstart", ".app", ".jsp", ".html"}

// Hashes
var md5Regex = regexp.MustCompile("[A-Fa-f0-9]{32}")
var sha1Regex = regexp.MustCompile("[A-Fa-f0-9]{40}")
var sha256Regex = regexp.MustCompile("[A-Fa-f0-9]{64}")
var sha512Regex = regexp.MustCompile("[A-Fa-f0-9]{128}")
var ssdeepRegex = regexp.MustCompile("\\d{2}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}")

// Network
var domainRegex = regexp.MustCompile("[0-9a-z-]+\\.[0-0a-z-]{2,255}(\\.[a-z]{2,255})?")
var emailRegex = regexp.MustCompile("[A-Za-z0-9_.]+@[0-9a-z.-]+")
var ipv4Regex = regexp.MustCompile("(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\[?\\.\\]?){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
var ipv6Regex = regexp.MustCompile("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")
var urlRegex = regexp.MustCompile("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")

// Files
var docRegex = regexp.MustCompile("([\\w-]+)(\\.docx|\\.doc|\\.csv|\\.pdf|\\.xlsx|\\.xls|\\.rtf|\\.txt|\\.pptx|\\.ppt|\\.pages|\\.keynote|\\.numbers)")
var exeRegex = regexp.MustCompile("([\\w-]+)(\\.exe|\\.dll|\\.jar)")
var flashRegex = regexp.MustCompile("([\\w-]+)(\\.flv|\\.swf)")
var imgRegex = regexp.MustCompile("([\\w-]+)(\\.jpeg|\\.jpg|\\.gif|\\.png|\\.tiff|\\.bmp)")
var macRegex = regexp.MustCompile("[%A-Za-z\\.\\-\\_\\/ ]+(\\.plist|\\.app|\\.pkg)")
var webRegex = regexp.MustCompile("([\\w-]+)(\\.html|\\.php|\\.js|\\.jsp|\\.asp)")
var zipRegex = regexp.MustCompile("([\\w-]+)(\\.zip|\\.zipx|\\.7z|\\.rar|\\.tar|\\.gz)")

// Utility
var cveRegex = regexp.MustCompile("(CVE-(19|20)\\d{2}-\\d{4,7})")

// Snort Signatures
// Yara Rules

func stringInSlice(element string, list []string) bool {
	for _, b := range list {
		if element == b {
			return true
		}
	}
	return false
}

func cleanIpv4(ips []string) []string {
	for index := 0; index < len(ips); index++ {
		ips[index] = strings.Replace(ips[index], "[", "", -1)
		ips[index] = strings.Replace(ips[index], "]", "", -1)
	}
	return ips
}

func cleanUrls(urls []string) []string {

	for index, value := range urls {
		if value[len(value)-1] == ')' {
			urls[index] = value[:len(value)-1]
		}
	}

	return urls
}

func cleanDomains(domains []string) []string {
	var cleanDomains []string

	for index := 0; index < len(domains); index++ {
		if !stringInSlice(domains[index], cleanDomains) {
			for _, v := range domainBlacklist {
				if !strings.Contains(domains[index], v) {
					cleanDomains = append(cleanDomains, domains[index])
				}
			}
		}
	}
	return cleanDomains
}

func main() {

	comments := flag.String("comment", "Automatically imported.", "Adds a note to the export.")
	tags := flag.String("tags", "", "Adds a list of tags to the export (comma seperated).")
	flag.Parse()

	tagslist := strings.Split(*tags, ",")

	// Get Data from STDIN
	bytes, _ := ioutil.ReadAll(os.Stdin)
	data := string(bytes)

	// Hashes
	md5s := Dedup(md5Regex.FindAllString(data, -1))
	sha1s := Dedup(sha1Regex.FindAllString(data, -1))
	sha256s := Dedup(sha256Regex.FindAllString(data, -1))
	sha512s := Dedup(sha512Regex.FindAllString(data, -1))
	ssdeeps := Dedup(ssdeepRegex.FindAllString(data, -1))

	// Network
	domains := Dedup(cleanDomains(domainRegex.FindAllString(data, -1)))
	emails := Dedup(emailRegex.FindAllString(data, -1))
	ipv4s := Dedup(cleanIpv4(ipv4Regex.FindAllString(data, -1)))
	ipv6s := Dedup(ipv6Regex.FindAllString(data, -1))
	urls := Dedup(cleanUrls(urlRegex.FindAllString(data, -1)))

	// Filenames
	docs := Dedup(docRegex.FindAllString(data, -1))
	exes := Dedup(exeRegex.FindAllString(data, -1))
	flashes := Dedup(flashRegex.FindAllString(data, -1))
	imgs := Dedup(imgRegex.FindAllString(data, -1))
	macs := Dedup(macRegex.FindAllString(data, -1))
	webs := Dedup(webRegex.FindAllString(data, -1))
	zips := Dedup(zipRegex.FindAllString(data, -1))

	// Utility
	cves := cveRegex.FindAllString(data, -1)

	c := &cacadordata{md5s, sha1s, sha256s, sha512s, ssdeeps, domains, emails, ipv4s, ipv6s, urls, docs, exes, flashes, imgs, macs, webs, zips, cves, *comments, tagslist, time.Now().String()}

	b, _ := json.Marshal(c)

	fmt.Println(string(b))
}
