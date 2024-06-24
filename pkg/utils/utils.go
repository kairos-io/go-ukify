package utils

import (
	"github.com/kairos-io/go-ukify/pkg/constants"
	"github.com/kairos-io/go-ukify/pkg/types"
)

// SectionsData transforms a []types.UkiSection into a map[constants.Section]string
// based on types.UkiSection.Measure being true
// So it obtains a list of sections that have to be measured
func SectionsData(sections []types.UkiSection) map[constants.Section]string {
	data := map[constants.Section]string{}
	for _, s := range sections {
		if s.Measure {
			data[s.Name] = s.Path
		}
	}
	// Mimic what xslices does if there is no data, we return nil
	if len(data) == 0 {
		return nil
	}
	return data
}
