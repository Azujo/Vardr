// SPDX-License-Identifier: AGPL-3.0-or-later

// Package msipatch podmienia w pliku MSI napis na inny o tej samej długości
// (wypełniacze właściwości SERVER i TOKEN instalatora agenta). MSI to plik
// Compound File Binary (CFB): strumienie są łańcuchami sektorów, małe
// strumienie (poniżej progu, zwykle 4096 B) leżą w ministrumieniu
// w 64-bajtowych minisektorach – napis bywa więc rozbity na nieciągłe
// fragmenty pliku. Pakiet odtwarza każdy strumień, szuka w nim napisu
// i zapisuje nowe bajty pod odpowiadającymi im pozycjami w pliku. Struktura
// (rozmiary, tabele, łańcuchy) się nie zmienia.
package msipatch

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

var signature = []byte{0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1}

const (
	endOfChain = 0xFFFFFFFE
	freeSect   = 0xFFFFFFFF
	maxSect    = 0xFFFFFFFA
)

type cfb struct {
	data       []byte
	sectorSize int
	miniSize   int
	miniCutoff uint64
	fat        []uint32
	miniFat    []uint32
	rootChain  []uint32 // łańcuch ministrumienia
}

func (c *cfb) sectorOffset(s uint32) int { return (int(s) + 1) * c.sectorSize }

func (c *cfb) u32(off int) uint32 { return binary.LittleEndian.Uint32(c.data[off:]) }

// chain zwraca łańcuch sektorów od start (FAT albo miniFAT).
func chain(table []uint32, start uint32, limit int) ([]uint32, error) {
	var out []uint32
	for s := start; s != endOfChain; {
		if s > maxSect || int(s) >= len(table) {
			return nil, fmt.Errorf("uszkodzony łańcuch sektorów (%d)", s)
		}
		out = append(out, s)
		if len(out) > limit {
			return nil, errors.New("pętla w łańcuchu sektorów")
		}
		s = table[s]
	}
	return out, nil
}

func parse(data []byte) (*cfb, error) {
	if len(data) < 512 || !bytes.Equal(data[:8], signature) {
		return nil, errors.New("to nie jest plik MSI (Compound File)")
	}
	c := &cfb{data: data}
	c.sectorSize = 1 << binary.LittleEndian.Uint16(data[0x1E:])
	c.miniSize = 1 << binary.LittleEndian.Uint16(data[0x20:])
	if c.sectorSize != 512 && c.sectorSize != 4096 || c.miniSize != 64 {
		return nil, errors.New("nieobsługiwany rozmiar sektora")
	}
	c.miniCutoff = uint64(c.u32(0x38))
	nSectors := len(data)/c.sectorSize - 1
	// DIFAT: 109 wpisów w nagłówku, dalej łańcuch sektorów DIFAT.
	var fatSectors []uint32
	for i := 0; i < 109; i++ {
		if s := c.u32(0x4C + 4*i); s <= maxSect {
			fatSectors = append(fatSectors, s)
		}
	}
	perSector := c.sectorSize / 4
	for s, n := c.u32(0x44), int(c.u32(0x48)); n > 0 && s <= maxSect; n-- {
		off := c.sectorOffset(s)
		if off+c.sectorSize > len(data) {
			return nil, errors.New("uszkodzona tablica DIFAT")
		}
		for i := 0; i < perSector-1; i++ {
			if v := c.u32(off + 4*i); v <= maxSect {
				fatSectors = append(fatSectors, v)
			}
		}
		s = c.u32(off + 4*(perSector-1))
	}
	for _, s := range fatSectors {
		off := c.sectorOffset(s)
		if off+c.sectorSize > len(data) {
			return nil, errors.New("uszkodzona tablica FAT")
		}
		for i := 0; i < perSector; i++ {
			c.fat = append(c.fat, c.u32(off+4*i))
		}
	}
	if mf := c.u32(0x3C); mf <= maxSect {
		ch, err := chain(c.fat, mf, nSectors)
		if err != nil {
			return nil, fmt.Errorf("miniFAT: %w", err)
		}
		for _, s := range ch {
			off := c.sectorOffset(s)
			for i := 0; i < perSector; i++ {
				c.miniFat = append(c.miniFat, c.u32(off+4*i))
			}
		}
	}
	return c, nil
}

// entry to wpis katalogu (strumień).
type entry struct {
	typ   byte
	start uint32
	size  uint64
}

func (c *cfb) entries() ([]entry, error) {
	nSectors := len(c.data)/c.sectorSize - 1
	ch, err := chain(c.fat, c.u32(0x30), nSectors)
	if err != nil {
		return nil, fmt.Errorf("katalog: %w", err)
	}
	var out []entry
	for _, s := range ch {
		off := c.sectorOffset(s)
		for i := 0; i < c.sectorSize/128; i++ {
			e := c.data[off+128*i : off+128*(i+1)]
			size := binary.LittleEndian.Uint64(e[120:])
			if c.sectorSize == 512 {
				size &= 0xFFFFFFFF // wersja 3: starsza połowa niezdefiniowana
			}
			out = append(out, entry{typ: e[66], start: binary.LittleEndian.Uint32(e[116:]), size: size})
		}
	}
	if len(out) == 0 || out[0].typ != 5 {
		return nil, errors.New("brak katalogu głównego")
	}
	if out[0].start <= maxSect {
		c.rootChain, err = chain(c.fat, out[0].start, nSectors)
		if err != nil {
			return nil, fmt.Errorf("ministrumień: %w", err)
		}
	}
	return out, nil
}

// offsets zwraca pozycję w pliku każdego bajtu strumienia.
func (c *cfb) offsets(e entry) ([]int, error) {
	nSectors := len(c.data)/c.sectorSize - 1
	out := make([]int, 0, e.size)
	if e.size < c.miniCutoff {
		ch, err := chain(c.miniFat, e.start, len(c.miniFat))
		if err != nil {
			return nil, err
		}
		for _, m := range ch {
			for i := 0; i < c.miniSize && uint64(len(out)) < e.size; i++ {
				pos := int(m)*c.miniSize + i // pozycja w ministrumieniu
				idx := pos / c.sectorSize
				if idx >= len(c.rootChain) {
					return nil, errors.New("minisektor poza ministrumieniem")
				}
				out = append(out, c.sectorOffset(c.rootChain[idx])+pos%c.sectorSize)
			}
		}
	} else {
		ch, err := chain(c.fat, e.start, nSectors)
		if err != nil {
			return nil, err
		}
		for _, s := range ch {
			for i := 0; i < c.sectorSize && uint64(len(out)) < e.size; i++ {
				out = append(out, c.sectorOffset(s)+i)
			}
		}
	}
	if uint64(len(out)) != e.size {
		return nil, errors.New("strumień krótszy niż jego rozmiar")
	}
	for _, o := range out {
		if o >= len(c.data) {
			return nil, errors.New("strumień poza plikiem")
		}
	}
	return out, nil
}

// Replace zwraca kopię pliku MSI z napisem old zastąpionym przez repl
// (repl dopełniany spacjami do długości old). Zwraca liczbę podmian;
// brak napisu albo za długa wartość to błąd.
func Replace(msi []byte, old, repl string) ([]byte, int, error) {
	if len(repl) > len(old) {
		return nil, 0, fmt.Errorf("wartość dłuższa niż %d znaków", len(old))
	}
	newb := []byte(repl + string(bytes.Repeat([]byte(" "), len(old)-len(repl))))
	c, err := parse(msi)
	if err != nil {
		return nil, 0, err
	}
	ents, err := c.entries()
	if err != nil {
		return nil, 0, err
	}
	out := bytes.Clone(msi)
	n := 0
	for _, e := range ents {
		if e.typ != 2 || e.size < uint64(len(old)) {
			continue
		}
		offs, err := c.offsets(e)
		if err != nil {
			return nil, 0, err
		}
		stream := make([]byte, len(offs))
		for i, o := range offs {
			stream[i] = msi[o]
		}
		for from := 0; ; {
			i := bytes.Index(stream[from:], []byte(old))
			if i < 0 {
				break
			}
			for j := range newb {
				out[offs[from+i+j]] = newb[j]
			}
			n++
			from += i + len(old)
		}
	}
	if n == 0 {
		return nil, 0, fmt.Errorf("w pliku MSI nie ma napisu %.24q… – instalator zbudowany bez wypełniaczy?", old)
	}
	return out, n, nil
}
