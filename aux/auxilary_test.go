package aux

import (
	"reflect"
	"testing"
)

func TestDedup(t *testing.T) {
	if !(len(Dedup([]string{"foo", "bar", "bar", "foo"})) == 2) {
		t.Error("Didn't remove the correct number of duplicate items.")
	}
	if !reflect.DeepEqual(Dedup([]string{"foo", "bar", "bar"}), []string{"foo", "bar"}) {
		t.Error("Didn't remove the correct items.")
	}
}

func TestCleanIPs(t *testing.T) {
	if !reflect.DeepEqual(CleanIpv4([]string{"1[.]2.3[.]4"}), []string{"1.2.3.4"}) {
		t.Error("Not removing brackets from IPs effectively.")
	}
	if !reflect.DeepEqual(CleanIpv4([]string{"1(.)2.3(.)4"}), []string{"1.2.3.4"}) {
		t.Error("Not removing parentheses from IPs effectively.")
	}
}

func TestCleanDomains(t *testing.T) {
	got := []string{"foo.com", "bar.com", "example.com", "mandiant.com", "www.us-cert.gov"}
	want := []string{"foo.com", "bar.com", "www.us-cert.gov"}

	if s := CleanDomains(got); !reflect.DeepEqual(s, want) {
		t.Errorf("Not removing blacklisted domains. %v", s)
	}
}

func TestCleanURLs(t *testing.T) {
	got := []string{"www.google.com/)"}
	want := []string{"www.google.com/"}

	if s := CleanUrls(got); !reflect.DeepEqual(s, want) {
		t.Errorf("Not removing bad URL characters. %v", s)
	}
}
