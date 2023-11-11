// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"fmt"
	"sort"

	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/signal"
)

type Canonicalizer struct {
	// Map of modules stored as module name:kernel module.
	modules map[string]host.KernelModule

	// Contains a sorted list of the canonical module addresses.
	moduleKeys []uint64
}

type CanonicalizerInstance struct {
	canonical Canonicalizer

	// Contains the canonicalize and decanonicalize conversion maps.
	canonicalize   *Convert
	decanonicalize *Convert
}

// Contains the current conversion maps used.
type Convert struct {
	conversionHash map[uint64]*canonicalizerModule
	moduleKeys     []uint64
}

type convertContext struct {
	errCount int
	errPC    uint64
	convert  *Convert
}

// Contains the offset and final address of each module.
type canonicalizerModule struct {
	offset  int
	endAddr uint64
	// Discard coverage from current module.
	// Set to true if module is not present in canonical.
	discard bool
}

func NewCanonicalizer(modules []host.KernelModule, flagSignal bool) *Canonicalizer {
	// Return if not using canonicalization.
	if len(modules) == 0 || !flagSignal {
		return &Canonicalizer{}
	}
	// Create a map of canonical module offsets by name.
	canonicalModules := make(map[string]host.KernelModule)
	for _, module := range modules {
		canonicalModules[module.Name] = module
	}

	// Store sorted canonical address keys.
	canonicalModuleKeys := make([]uint64, len(modules))
	setModuleKeys(canonicalModuleKeys, modules)
	return &Canonicalizer{
		modules:    canonicalModules,
		moduleKeys: canonicalModuleKeys,
	}
}

func (can *Canonicalizer) NewInstance(modules []host.KernelModule) *CanonicalizerInstance {
	if can.moduleKeys == nil {
		return &CanonicalizerInstance{}
	}
	// Save sorted list of module offsets.
	moduleKeys := make([]uint64, len(modules))
	setModuleKeys(moduleKeys, modules)

	// Create a hash between the "canonical" module addresses and each VM instance.
	instToCanonicalMap := make(map[uint64]*canonicalizerModule)
	canonicalToInstMap := make(map[uint64]*canonicalizerModule)
	for _, module := range modules {
		discard := false
		canonicalAddr := uint64(0)
		canonicalModule, found := can.modules[module.Name]
		if !found || canonicalModule.Size != module.Size {
			log.Errorf("kernel build has changed; instance module %v differs from canonical", module.Name)
			discard = true
		}
		if found {
			canonicalAddr = uint64(canonicalModule.Addr)
		}

		instAddr := uint64(module.Addr)

		canonicalToInstMap[canonicalAddr] = &canonicalizerModule{
			offset:  int(instAddr) - int(canonicalAddr),
			endAddr: uint64(module.Size) + canonicalAddr,
			discard: discard,
		}

		instToCanonicalMap[instAddr] = &canonicalizerModule{
			offset:  int(canonicalAddr) - int(instAddr),
			endAddr: uint64(module.Size) + instAddr,
			discard: discard,
		}
	}

	return &CanonicalizerInstance{
		canonical: *can,
		canonicalize: &Convert{
			conversionHash: instToCanonicalMap,
			moduleKeys:     moduleKeys,
		},
		decanonicalize: &Convert{
			conversionHash: canonicalToInstMap,
			moduleKeys:     can.moduleKeys,
		},
	}
}

func (ci *CanonicalizerInstance) Canonicalize(cov []uint64, sign signal.Serial) ([]uint64, signal.Serial) {
	if ci.canonical.moduleKeys == nil {
		return cov, sign
	}
	return ci.canonicalize.convertPCs(cov, sign)
}

func (ci *CanonicalizerInstance) Decanonicalize(cov []uint64, sign signal.Serial) ([]uint64, signal.Serial) {
	if ci.canonical.moduleKeys == nil {
		return cov, sign
	}
	return ci.decanonicalize.convertPCs(cov, sign)
}

func (ci *CanonicalizerInstance) DecanonicalizeFilter(bitmap map[uint64]uint64) map[uint64]uint64 {
	// Skip conversion if modules or filter are not used.
	if ci.canonical.moduleKeys == nil || len(bitmap) == 0 {
		return bitmap
	}
	instBitmap := make(map[uint64]uint64)
	convCtx := &convertContext{convert: ci.decanonicalize}
	for pc, val := range bitmap {
		if newPC, ok := ci.decanonicalize.convertPC(pc); ok {
			instBitmap[newPC] = val
		} else {
			convCtx.discard(pc)
		}
	}
	if msg := convCtx.discarded(); msg != "" {
		log.Logf(4, "error in bitmap conversion: %v", msg)
	}
	return instBitmap
}

// Store sorted list of addresses. Used to binary search when converting PCs.
func setModuleKeys(moduleKeys []uint64, modules []host.KernelModule) {
	for idx, module := range modules {
		// Truncate PCs to uint64, assuming that they fit into 32 bits.
		// True for x86_64 and arm64 without KASLR.
		moduleKeys[idx] = uint64(module.Addr)
	}

	// Sort modules by address.
	sort.Slice(moduleKeys, func(i, j int) bool { return moduleKeys[i] < moduleKeys[j] })
}

func findModule(pc uint64, moduleKeys []uint64) (moduleIdx int) {
	moduleIdx, _ = sort.Find(len(moduleKeys), func(moduleIdx int) int {
		if pc < moduleKeys[moduleIdx] {
			return -1
		}
		return +1
	})
	// Sort.Find returns the index above the correct module.
	return moduleIdx - 1
}

func (convert *Convert) convertPCs(cov []uint64, sign signal.Serial) ([]uint64, signal.Serial) {
	// Convert coverage.
	var retCov []uint64
	convCtx := &convertContext{convert: convert}
	for _, pc := range cov {
		if newPC, ok := convert.convertPC(pc); ok {
			retCov = append(retCov, newPC)
		} else {
			convCtx.discard(pc)
		}
	}
	if msg := convCtx.discarded(); msg != "" {
		log.Logf(4, "error in PC conversion: %v", msg)
	}
	// Convert signals.
	retSign := &signal.Serial{}
	convCtx = &convertContext{convert: convert}
	for idx, elem := range sign.Elems {
		if newSign, ok := convert.convertPC(uint64(elem)); ok {
			retSign.AddElem(uint32(newSign&0xffffffff), sign.Prios[idx])
		} else {
			convCtx.discard(uint64(elem))
		}
	}
	if msg := convCtx.discarded(); msg != "" {
		log.Logf(4, "error in signal conversion: %v", msg)
	}
	return retCov, *retSign
}

func (convert *Convert) convertPC(pc uint64) (uint64, bool) {
	moduleIdx := findModule(pc, convert.moduleKeys)
	// Check if address is above the first module offset.
	if moduleIdx >= 0 {
		module, found := convert.conversionHash[convert.moduleKeys[moduleIdx]]
		if !found {
			return pc, false
		}
		// If the address is within the found module add the offset.
		if pc < module.endAddr {
			if module.discard {
				return pc, false
			}
			pc = uint64(int(pc) + module.offset)
		}
	}
	return pc, true
}

func (cc *convertContext) discarded() string {
	if cc.errCount == 0 {
		return ""
	}
	errMsg := fmt.Sprintf("discarded 0x%x (and %v other PCs) during conversion", cc.errPC, cc.errCount)
	return fmt.Sprintf("%v; not found in module map", errMsg)
}

func (cc *convertContext) discard(pc uint64) {
	cc.errCount += 1
	if cc.errPC == 0 {
		cc.errPC = pc
	}
}
