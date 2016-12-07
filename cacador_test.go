package main

import "testing"

func TestGetUtilityStrings(t *testing.T) {
	data := "foo bar CVE-2000-0001 baz"
	want := "CVE-2000-0001"

	if got := GetUtilityStrings(data).Cves[0]; got != want {
		t.Errorf("GetUtilityStrings(%q) = %v", want, got)
	}
}

// func TestGetHashStrings(t *testing.T) {
//
// 	GetHashStrings(data)
// }
