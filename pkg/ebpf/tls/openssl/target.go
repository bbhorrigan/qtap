package openssl

import (
	"debug/elf"
	"errors"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/qpoint-io/qtap/pkg/binutils"
	"github.com/qpoint-io/qtap/pkg/ebpf/common"
	"go.uber.org/zap"
)

// enum for target type
type TargetType int

const (
	TargetTypeShared TargetType = iota
	TargetTypeStatic
)

type OpenSSLTarget struct {
	// name
	name string

	// container
	containerID string

	// type
	type_ TargetType

	// logger
	logger *zap.Logger

	// absolute path to the target location
	location string

	// cache entry
	cacheEntry *ScanResult

	// uprobes
	probes []*common.Uprobe

	// elf file
	ef *binutils.Elf
}

func NewOpenSSLTarget(logger *zap.Logger, name, containerID, location string, ef *binutils.Elf, type_ TargetType, probes []*common.Uprobe, cacheEntry *ScanResult) *OpenSSLTarget {
	return &OpenSSLTarget{
		logger:      logger,
		name:        name,
		containerID: containerID,
		location:    location,
		ef:          ef,
		type_:       type_,
		probes:      probes,
		cacheEntry:  cacheEntry,
	}
}

func (t *OpenSSLTarget) Start() error {
	// create a link to the executable
	ex, err := link.OpenExecutable(t.location)
	if err != nil {
		return fmt.Errorf("opening executable: %w", err)
	}

	// probes := []struct {
	// 	Symbol   string
	// 	Prog     *ebpf.Program
	// 	IsReturn bool
	// }{
	// 	// ssl probes for anything that implements openssl
	// 	{Symbol: "SSL_read", Prog: t.objs.OpensslProbeEntrySSL_read, IsReturn: false},
	// 	{Symbol: "SSL_read_ex", Prog: t.objs.OpensslProbeEntrySSL_readEx, IsReturn: false},
	// 	{Symbol: "SSL_write", Prog: t.objs.OpensslProbeEntrySSL_write, IsReturn: false},
	// 	{Symbol: "SSL_write_ex", Prog: t.objs.OpensslProbeEntrySSL_writeEx, IsReturn: false},

	// 	{Symbol: "SSL_read", Prog: t.objs.OpensslProbeRetSSL_read, IsReturn: true},
	// 	{Symbol: "SSL_read_ex", Prog: t.objs.OpensslProbeRetSSL_readEx, IsReturn: true},
	// 	{Symbol: "SSL_write", Prog: t.objs.OpensslProbeRetSSL_write, IsReturn: true},
	// 	{Symbol: "SSL_write_ex", Prog: t.objs.OpensslProbeRetSSL_writeEx, IsReturn: true},
	// 	{Symbol: "SSL_new", Prog: t.objs.OpensslProbeRetSSL_new, IsReturn: true},
	// 	{Symbol: "SSL_free", Prog: t.objs.OpensslProbeEntrySSL_free, IsReturn: false},
	// }

	// searched symbols to use
	var syms []elf.Symbol

	// if we have a cache entry, use it
	if t.cacheEntry != nil && t.cacheEntry.Symbols != nil {
		syms = t.cacheEntry.Symbols
	}

	if syms == nil {
		// create a symbol search from the probes
		search := []binutils.SymbolSearch{}
		for _, p := range t.probes {
			search = append(search, binutils.SymbolSearch{
				Name:          p.Function,
				MatchStrategy: binutils.MatchStrategyExact,
			})
		}

		// open the ELF file if we don't have one
		if t.ef == nil {
			ef, err := binutils.NewElf(t.location, "/", false)
			if err != nil {
				return err
			}
			t.ef = ef

			defer t.ef.Close()
		}

		// find the symbols from the binary
		syms, err = t.ef.SearchSymbols(search, elf.SHT_SYMTAB, elf.SHT_DYNSYM)
		if err != nil && !errors.Is(err, binutils.ErrNoSymbols) {
			t.logger.Debug("Failed to search for symbols", zap.Error(err))
		}

		// calculate the addresses of the symbols
		syms = t.ef.CalculateUprobeAddresses(syms)

		// cache the result
		if t.cacheEntry != nil {
			t.cacheEntry.Symbols = syms
		}
	}

	// attach all of the probes
	for _, probe := range t.probes {
		var err error

		// ensure the symbol exists
		for _, sym := range syms {
			if sym.Name == probe.Function {
				// if this is a static target, let's ensure the symbol is embedded
				if t.type_ == TargetTypeStatic {
					if sym.Value == 0 || sym.Size == 0 {
						continue
					}
				}

				// debug
				if !probe.IsRet {
					t.logger.Debug("Attaching OpenSSL probe",
						zap.String("target", t.name),
						zap.String("container_id", t.containerID),
						zap.String("function (symbol)", probe.Function),
						zap.Uint64("address", sym.Value),
					)
				}

				err = probe.Attach(ex, sym.Value)
				if err != nil {
					return fmt.Errorf("attaching probe to %s:%w", probe.Function, err)
				}

				break
			}
		}
	}

	return nil
}

func (t *OpenSSLTarget) Stop() error {
	// disconnect all of the probes
	for _, ln := range t.probes {
		if err := ln.Detach(); err != nil {
			return fmt.Errorf("closing probe link: %w", err)
		}
	}

	return nil
}
