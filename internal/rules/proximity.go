package rules

// CheckProximity verifies that all required auxiliary patterns for a composite
// rule are found within the specified proximity of the primary match.
// lines is a slice of surrounding lines, centerIdx is the index of the primary
// match line within that slice, and centerCol is the column of the match.
func (r *CompiledRule) CheckProximity(lines []string, centerIdx, centerCol int) bool {
	if len(r.Required) == 0 {
		return true
	}

	for _, req := range r.Required {
		if !findRequired(req, lines, centerIdx, centerCol) {
			return false
		}
	}
	return true
}

func findRequired(req CompiledRequired, lines []string, centerIdx, centerCol int) bool {
	for i, line := range lines {
		lineDist := i - centerIdx
		if lineDist < 0 {
			lineDist = -lineDist
		}

		// Check vertical proximity.
		if req.WithinLines > 0 && lineDist > req.WithinLines {
			continue
		}

		locs := req.Regex.FindStringIndex(line)
		if locs == nil {
			continue
		}

		// Check horizontal proximity if specified.
		if req.WithinColumns > 0 && i == centerIdx {
			colDist := locs[0] - centerCol
			if colDist < 0 {
				colDist = -colDist
			}
			if colDist > req.WithinColumns {
				continue
			}
		}

		return true
	}
	return false
}
