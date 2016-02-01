package main

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
    "regexp"
    "strings"
)

type CacadorData struct {
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
    Cves    []string
}

// Hashes
var md5_regex = regexp.MustCompile("[A-Fa-f0-9]{32}")
var sha1_regex = regexp.MustCompile("[A-Fa-f0-9]{40}")
var sha256_regex = regexp.MustCompile("[A-Fa-f0-9]{64}")
var sha512_regex = regexp.MustCompile("[A-Fa-f0-9]{128}")
var ssdeep_regex = regexp.MustCompile("\\d{2}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}")

// Network
var domain_regex = regexp.MustCompile("[A-za-z]+\\.[a-z]{2,255}(\\.[a-z]{2,255})?")
var email_regex = regexp.MustCompile("[A-Za-z0-9_.]+@[0-9a-z.-]+")
var ipv4_regex = regexp.MustCompile("(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\[?\\.\\]?){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
var ipv6_regex = regexp.MustCompile("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")
var url_regex = regexp.MustCompile("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")

// Files
var doc_regex = regexp.MustCompile("([\\w-]+)(\\.docx|\\.doc|\\.csv|\\.pdf|\\.xlsx|\\.xls|\\.rtf|\\.txt|\\.pptx|\\.ppt|\\.pages|\\.keynote|\\.numbers)")
var exe_regex = regexp.MustCompile("([\\w-]+)(\\.exe|\\.dll|\\.jar)")
var flash_regex = regexp.MustCompile("([\\w-]+)(\\.flv|\\.swf)")
var img_regex = regexp.MustCompile("([\\w-]+)(\\.jpeg|\\.jpg|\\.gif|\\.png|\\.tiff|\\.bmp)")
var mac_regex = regexp.MustCompile("[%A-Za-z\\.\\-\\_\\/ ]+(\\.plist|\\.app|\\.pkg)")
var web_regex = regexp.MustCompile("([\\w-]+)(\\.html|\\.php|\\.js)")
var zip_regex = regexp.MustCompile("([\\w-]+)(\\.zip|\\.zipx|\\.7z|\\.rar|\\.tar|\\.gz)")

// Utility
var cve_regex = regexp.MustCompile("(CVE-(19|20)\\d{2}-\\d{4,7})")
// Snort Signatures
// Yara Rules

func clean_ipv4(ips []string) []string {
    for index := 0; index < len(ips); index++ {
        ips[index] = strings.Replace(ips[index], "[", "", -1)
        ips[index] = strings.Replace(ips[index], "]", "", -1)
    }
    return ips
}

func main() {

    // Get Data from STDIN
    bytes, _ := ioutil.ReadAll(os.Stdin)
    data := string(bytes)

    // Hashes
    md5s := md5_regex.FindAllString(data, -1)
    sha1s := sha1_regex.FindAllString(data, -1)
    sha256s := sha256_regex.FindAllString(data, -1)
    sha512s := sha512_regex.FindAllString(data, -1)
    ssdeeps := ssdeep_regex.FindAllString(data, -1)

    // Network
    domains := domain_regex.FindAllString(data, -1)
    emails := email_regex.FindAllString(data, -1)
    ipv4s := clean_ipv4(ipv4_regex.FindAllString(data, -1))
    ipv6s := ipv6_regex.FindAllString(data, -1)
    urls := url_regex.FindAllString(data, -1)

    // Filenames
    docs := doc_regex.FindAllString(data, -1)
    exes := exe_regex.FindAllString(data, -1)
    flashes := flash_regex.FindAllString(data, -1)
    imgs := img_regex.FindAllString(data, -1)
    macs := mac_regex.FindAllString(data, -1)
    webs := web_regex.FindAllString(data, -1)
    zips := zip_regex.FindAllString(data, -1)

    // Utility
    cves := cve_regex.FindAllString(data, -1)

    c := &CacadorData{md5s, sha1s, sha256s, sha512s, ssdeeps, domains, emails, ipv4s, ipv6s, urls, docs, exes, flashes, imgs, macs, webs, zips, cves}

    b, _ := json.Marshal(c)

    fmt.Println(string(b))
}
