package aux

import "testing"

func TestIsHash(t *testing.T) {
	var tests = []struct {
		input string
		want  bool
	}{
		{"874058e8d8582bf85c115ce319c5b0af", true},
		{"874058e8d8582bf85c115ce319c5b0a", false},
		// needs more samples
	}

	for _, test := range tests {
		if got := IsHash(test.input); got != test.want {
			t.Errorf("IsHash(%q) = %v", test.input, got)
		}
	}

}

func TestIsNetworkIoc(t *testing.T) {
	var tests = []struct {
		input string
		want  bool
	}{
		{"8.8.8.8", true},
		{"300.300.300.300", false},
		{"test@test.com", true},
		{"example.com", true},
		{"example.pumpkin", false},
		{"https://www.example.com/foo/bar?baz=1", true},
	}

	for _, test := range tests {
		if got := IsNetworkIoc(test.input); got != test.want {
			t.Errorf("IsNetworkIoc(%q) = %v", test.input, got)
		}
	}
}

func TestIsFileIoc(t *testing.T) {
	var tests = []struct {
		input string
		want  bool
	}{
		{"test.doc", true},
		{"test.dl", false},
		{"test.dll", true},
		{"test.jpg", true},
		{"example.pumpkin", false},
	}

	for _, test := range tests {
		if got := IsFileIoc(test.input); got != test.want {
			t.Errorf("IsFileIoc(%q) = %v", test.input, got)
		}
	}
}

func TestIsUtilityItem(t *testing.T) {
	var tests = []struct {
		input string
		want  bool
	}{
		{"CVE-1800-0000", false},
		{"CVE-2016-0000", true},
		{"CVE-2100-0000", false},
		{"CVE-2016-00000", true},
		{"CVE-20100-0000", false},
	}

	for _, test := range tests {
		if got := IsUtilityItem(test.input); got != test.want {
			t.Errorf("IsUtilityItem(%q) = %v", test.input, got)
		}
	}
}
