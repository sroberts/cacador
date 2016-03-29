package main

import (
	"strings"
)

//StringInSlice identifies if a string is in a slice
func stringInSlice(element string, list []string) bool {
	for _, b := range list {
		if element == b {
			return true
		}
	}
	return false
}

//Dedup removes duplicate items from an array of strings and fixes empty arrays
func dedup(duplist []string) []string {
	var cleanList []string

	for _, v := range duplist {
		if !stringInSlice(v, cleanList) {
			cleanList = append(cleanList, v)
		}
	}

	if cleanList == nil {
		cleanList = []string{}
	}

	return cleanList
}

func cleanIpv4(ips []string) []string {
	for index := 0; index < len(ips); index++ {
		ips[index] = strings.Replace(ips[index], "[", "", -1)
		ips[index] = strings.Replace(ips[index], "]", "", -1)
	}
	return dedup(ips)
}

func cleanUrls(urls []string) []string {

	for index, value := range urls {
		if value[len(value)-1] == ')' {
			urls[index] = value[:len(value)-1]
		}
	}

	return dedup(urls)
}

func cleanDomains(domains []string) []string {
	var cleanDomains []string

	for index := 0; index < len(domains); index++ {
		if !stringInSlice(domains[index], cleanDomains) {
			for _, v := range domainBlacklist {
				if !v.MatchString(domains[index]) {
					cleanDomains = append(cleanDomains, domains[index])
				}
			}
		}
	}
	return dedup(cleanDomains)
}
