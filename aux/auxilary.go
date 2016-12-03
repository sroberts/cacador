package aux

import "strings"

//StringInSlice identifies if a string is in a slice
func StringInSlice(element string, list []string) bool {
	for _, b := range list {
		if element == b {
			return true
		}
	}
	return false
}

//Dedup removes duplicate items from an array of strings and fixes empty arrays
func Dedup(duplist []string) []string {
	var cleanList []string

	for _, v := range duplist {
		if !StringInSlice(v, cleanList) {
			cleanList = append(cleanList, v)
		}
	}

	// I think this is redundent code, but until test coverage is better I can't know
	// if cleanList == nil {
	// 	cleanList = []string{}
	// }

	return cleanList
}

// CleanIpv4 removes defanged ipv4 addresses
func CleanIpv4(ips []string) []string {
	for index := 0; index < len(ips); index++ {
		ips[index] = strings.Replace(ips[index], "[", "", -1)
		ips[index] = strings.Replace(ips[index], "]", "", -1)
		ips[index] = strings.Replace(ips[index], "(", "", -1)
		ips[index] = strings.Replace(ips[index], ")", "", -1)
	}
	return Dedup(ips)
}

// CleanUrls removes bad url values
func CleanUrls(urls []string) []string {

	for index, value := range urls {
		if value[len(value)-1] == ')' {
			urls[index] = value[:len(value)-1]
		}
	}

	return Dedup(urls)
}

// CleanDomains checks domains against blacklist to ensure low false positives
func CleanDomains(domains []string) []string {
	var cleanDomains []string

	for _, domain := range domains {
		if !IsBlacklisted(domain) {
			cleanDomains = append(cleanDomains, domain)
		}
	}

	return Dedup(cleanDomains)
}
