package tools

import (
	"regexp"
	"strings"
)

func NormalizeURLPath(path string) string {
	tokens := tokenizePath(path)
	normalizedTokens := normalizeSegments(tokens)

	newPath := assemblePath(normalizedTokens)
	if newPath[0] != '/' {
		newPath = "/" + newPath
	}

	return newPath
}

func tokenizePath(path string) []string {
	tokens := strings.Split(path, "/")
	filteredTokens := make([]string, 0)

	for _, token := range tokens {
		if len(token) > 0 {
			filteredTokens = append(filteredTokens, token)
		}
	}

	return filteredTokens
}

func assemblePath(segments []string) string {
	return "/" + strings.Join(segments, "/")
}

func isLikelyWord(input string) bool {
	matched, _ := regexp.MatchString("^[A-Za-z]+$", input)
	isReasonableLength := len(input) > 3 && len(input) <= 20

	return matched && isReasonableLength
}

func normalizeSegments(segments []string) []string {
	if len(segments) <= 1 {
		return segments
	}

	n := []string{}

	for i := range segments {
		if segments[i] == "" {
			continue
		}

		if !isLikelyWord(segments[i]) {
			resourceName := "id"
			if i > 0 {
				if isLikelyWord(segments[i-1]) {
					resourceName = segments[i-1]
				} else if strings.HasPrefix(segments[i-1], "{") {
					re := regexp.MustCompile(`\{(.+?)Id\}`)
					match := re.FindStringSubmatch(segments[i-1])
					if match != nil {
						resourceName = match[1]
					}
				}
			}
			segments[i] = "{" + resourceName + "Id}"
		}

		n = append(n, segments[i])
	}
	return n
}
