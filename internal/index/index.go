package index

import (
	"github.com/suga/tessaraop/internal/bitset"
	"github.com/suga/tessaraop/internal/model"
)

type FieldIndex struct {
	values      map[string]*bitset.Bitset
	noCondition *bitset.Bitset
}

type IndexSet struct {
	fields   map[string]*FieldIndex
	universe *bitset.Bitset
	n        int
}

func Build(policies []model.Policy) *IndexSet {
	n := len(policies)
	universe := bitset.New(n)
	for i := 0; i < n; i++ {
		universe.Set(i)
	}

	attrs := make(map[string]bool)
	for _, p := range policies {
		for _, c := range p.Conditions {
			if c.Operator == model.OpRange {
				continue
			}
			attrs[c.Attribute] = true
		}
	}

	fields := make(map[string]*FieldIndex, len(attrs))
	for attr := range attrs {
		hasCondition := bitset.New(n)
		valMap := make(map[string]*bitset.Bitset)

		for i, p := range policies {
			for _, c := range p.Conditions {
				if c.Attribute != attr || c.Operator == model.OpRange {
					continue
				}
				hasCondition.Set(i)
				for _, v := range c.Values {
					bs, ok := valMap[v]
					if !ok {
						bs = bitset.New(n)
						valMap[v] = bs
					}
					bs.Set(i)
				}
			}
		}

		fields[attr] = &FieldIndex{
			values:      valMap,
			noCondition: universe.Xor(hasCondition),
		}
	}

	return &IndexSet{
		fields:   fields,
		universe: universe,
		n:        n,
	}
}

func (idx *IndexSet) Candidates(req model.Request) []int {
	candidates := idx.universe.Clone()

	for attr, val := range req.Attributes {
		fi, ok := idx.fields[attr]
		if !ok {
			continue
		}

		valBits, hasVal := fi.values[val]
		var attrCandidates *bitset.Bitset
		if hasVal {
			attrCandidates = valBits.Or(fi.noCondition)
		} else {
			attrCandidates = fi.noCondition
		}
		candidates = candidates.And(attrCandidates)
	}

	return candidates.Ones()
}
