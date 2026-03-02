package detect

// Finding represents a single detected secret instance.
type Finding struct {
	File  string
	Line  int
	Rule  string // internal rule identifier
	Type  string // human-readable type, e.g. "AWS Access Key (AKIA...)"
	Value string // the matched secret value or token
}

// RuleDef describes a detection rule backed by a regex or other detector.
type RuleDef struct {
	ID          string
	Type        string
	Description string
}

