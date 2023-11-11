// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package cover provides types for working with coverage information (arrays of covered PCs).
package cover

type Cover map[uint64]struct{}

func (c Cover) Len() int {
	return len(c)
}

func (c Cover) Empty() bool {
	return len(c) == 0
}

func (c Cover) Copy() Cover {
	cc := make(Cover, len(c))
	for e, p := range c {
		cc[e] = p
	}
	return cc
}

func FromRaw(raw []uint64) Cover {
	if len(raw) == 0 {
		return nil
	}
	res := make(Cover, len(raw))
	for _, pc := range raw {
		res[pc] = struct{}{}
	}
	return res
}

func (cov Cover) Add(key uint64, value struct{}) {
	cov[key] = value
}

func (cov *Cover) Merge(raw Cover) {
	c := *cov
	if c == nil {
		c = make(Cover)
		*cov = c
	}
	for pc := range raw {
		c[pc] = struct{}{}
	}
}

func (cov *Cover) MergeRaw(raw []uint64) {
	c := *cov
	if c == nil {
		c = make(Cover)
		*cov = c
	}
	for _, pc := range raw {
		c[pc] = struct{}{}
	}
}

func (cov *Cover) Diff(raw Cover) Cover {
	if raw.Empty() {
		return nil
	}
	c := *cov
	if c == nil {
		c = make(Cover)
		*cov = c
	}
	var res Cover
	n := 0
	for pc := range raw {
		if _, ok := c[pc]; ok {
			continue
		}
		if res == nil {
			res = make(Cover)
		}
		res[pc] = struct{}{}
		n++
	}
	return res
}

func (cov *Cover) DiffRaw(raw []uint64) Cover {
	if len(raw) == 0 {
		return nil
	}
	c := *cov
	if c == nil {
		c = make(Cover)
		*cov = c
	}
	var res Cover
	n := 0
	for _, pc := range raw {
		if _, ok := c[pc]; ok {
			continue
		}
		if res == nil {
			res = make(Cover)
		}
		res[pc] = struct{}{}
		n++
	}
	return res
}

func (cov Cover) Serialize() []uint64 {
	res := make([]uint64, 0, len(cov))
	for pc, _ := range cov {
		res = append(res, pc)
	}
	return res
}

// Merge merges raw into coverage and returns newly added PCs. Overwrites/mutates raw.
func (cov *Cover) MergeDiffRaw(raw []uint64) []uint64 {
	c := *cov
	if c == nil {
		c = make(Cover)
		*cov = c
	}
	n := 0
	for _, pc := range raw {
		if _, ok := c[pc]; ok {
			continue
		}
		c[pc] = struct{}{}
		raw[n] = pc
		n++
	}
	return raw[:n]
}
