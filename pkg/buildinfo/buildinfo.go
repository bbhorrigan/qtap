package buildinfo

// this is set by the build process
var (
	version   string
	commit    string
	branch    string
	buildTime string
)

func Version() string {
	if version == "" {
		return "dev"
	}
	return version
}

func Commit() string {
	if commit == "" {
		return "unknown"
	}
	return commit
}

func Branch() string {
	if branch == "" {
		return "unknown"
	}
	return branch
}

func BuildTime() string {
	if buildTime == "" {
		return "unknown"
	}
	return buildTime
}
