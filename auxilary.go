package main

//Dedup removes duplicate items from an array of strings
func Dedup(duplist []string) []string {
	var cleanList []string

	for _, v := range duplist {
		if !stringInSlice(v, cleanList) {
			cleanList = append(cleanList, v)
		}
	}

	return cleanList
}
