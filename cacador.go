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
    Webs    []string
    Zips    []string

    // Utility
    Cves    []string
}

// func createJson () string  {
  // group_json = {
  //   'group_name': [
  //       '?'
  //   ],
  //   'attribution': [
  //       '?'
  //   ],
  //   'indicators': {
  //       'ips': extract_ips(text),
  //       'urls': extract_urls(text),
  //       'domains': extract_domains(text),
  //       'emails': extract_emails(text)
  //   },
  //   'malware': {
  //       'filenames': extract_filenames(text),
  //       'hashes': extract_hashes(text)
  //   },
  //   'cves': extract_cves(text),
  //   'metadata': {
  //       'report_name': '??',
  //       'date_analyzed': time.strftime('%Y-%m-%d %H:%M'),
  //       'source': '??',
  //       'release_date': '??',
  //       'tlp': tlp,
  //       'authors': [
  //           '??'
  //       ],
  //       'file_metadata': metadata
  //   }
  // }
// }

// Hashes
var md5_regex = regexp.MustCompile("[A-Fa-f0-9]{32}")
var sha1_regex = regexp.MustCompile("[A-Fa-f0-9]{40}")
var sha256_regex = regexp.MustCompile("[A-Fa-f0-9]{64}")
var sha512_regex = regexp.MustCompile("[A-Fa-f0-9]{128}")
var ssdeep_regex = regexp.MustCompile("\\d{2}:[A-Za-z0-9/+]{3,}:[A-Za-z0-9/+]{3,}")

// Network
var domain_regex = regexp.MustCompile("\b[A-za-z]+\\.[a-z]{2,255}(\\.[a-z]{2,255})?\b")
var email_regex = regexp.MustCompile("\b[A-Za-z0-9_.]+@[0-9a-z.-]+\b")
var ipv4_regex = regexp.MustCompile("(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\[?\\.\\]?){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)")
var ipv6_regex = regexp.MustCompile("(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")
var url_regex = regexp.MustCompile("http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+")

// Files
var doc_regex = regexp.MustCompile("\b([\\w-]+\\.)(docx|doc|csv|pdf|xlsx|xls|rtf|txt|pptx|ppt)\b")
var exe_regex = regexp.MustCompile("\b([\\w-]+\\.)(exe|dll|jar)\b")
var flash_regex = regexp.MustCompile("\b([\\w-]+\\.)(flv|swf)\b")
var img_regex = regexp.MustCompile("\b([\\w-]+\\.)(jpeg|jpg|gif|png|tiff|bmp)\b")
var web_regex = regexp.MustCompile("\b([\\w-]+\\.)(html|php|js)\b")
var zip_regex = regexp.MustCompile("\b([\\w-]+\\.)(zip|zipx|7z|rar|tar|gz)\b")

// Utility
var cve_regex = regexp.MustCompile("(CVE-(19|20)\\d{2}-\\d{4,7})")
// Snort Signatures
// Yara Rules

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
    ipv4s := ipv4_regex.FindAllString(data, -1)
    ipv6s := ipv6_regex.FindAllString(data, -1)
    urls := url_regex.FindAllString(data, -1)

    // Filenames
    docs := doc_regex.FindAllString(data, -1)
    exes := exe_regex.FindAllString(data, -1)
    flashes := flash_regex.FindAllString(data, -1)
    imgs := img_regex.FindAllString(data, -1)
    webs := web_regex.FindAllString(data, -1)
    zips := zip_regex.FindAllString(data, -1)

    // Utility
    cves := cve_regex.FindAllString(data, -1)

    fmt.Println("Hashes: ")
    fmt.Println("- md5s:" + strings.Join(md5s, ", "))
    fmt.Println("- sha1s:" + strings.Join(sha1s, ", "))
    fmt.Println("- sha256s:" + strings.Join(sha256s, ", "))
    fmt.Println("- sha512s:" + strings.Join(sha512s, ", "))
    fmt.Println("- ssdeeps:" + strings.Join(ssdeeps, ", "))

    fmt.Println("Network")
    fmt.Println("- domains:" + strings.Join(domains, ", "))
    fmt.Println("- emails:" + strings.Join(emails, ", "))
    fmt.Println("- ipv4s:" + strings.Join(ipv4s, ", "))
    fmt.Println("- ipv6:" + strings.Join(ipv6s, ", "))
    fmt.Println("- urls:" + strings.Join(urls, ", "))

    c := &CacadorData{md5s, sha1s, sha256s, sha512s, ssdeeps, domains, emails, ipv4s, ipv6s, urls, docs, exes, flashes, imgs, webs, zips, cves}

    b, _ := json.Marshal(c)

    fmt.Println(string(b))
}
