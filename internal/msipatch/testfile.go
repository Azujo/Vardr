// SPDX-License-Identifier: AGPL-3.0-or-later

package msipatch

import (
	"bytes"
	"encoding/binary"
)

// TestFile składa minimalny plik CFB do testów (także w innych pakietach):
// wersja 3, sektory 512 B –
// sektor 0 – FAT, 1 – katalog, 2 – miniFAT, 3–4 – ministrumień,
// 5–14 – duży strumień (łańcuch nieciągły: 5,7,9,…,6,8,…).
// Mały strumień zajmuje minisektory w kolejności 3,0,7,1 (nieciągle).
func TestFile(small, big []byte) []byte {
	const ss = 512
	file := make([]byte, ss*16)
	copy(file, signature)
	le := binary.LittleEndian
	le.PutUint16(file[0x1A:], 3)
	le.PutUint16(file[0x1C:], 0xFFFE)
	le.PutUint16(file[0x1E:], 9)
	le.PutUint16(file[0x20:], 6)
	le.PutUint32(file[0x2C:], 1) // sektory FAT
	le.PutUint32(file[0x30:], 1) // katalog
	le.PutUint32(file[0x38:], 4096)
	le.PutUint32(file[0x3C:], 2) // miniFAT
	le.PutUint32(file[0x40:], 1)
	le.PutUint32(file[0x44:], endOfChain)
	for i := 0; i < 109; i++ {
		le.PutUint32(file[0x4C+4*i:], freeSect)
	}
	le.PutUint32(file[0x4C:], 0)
	sec := func(n int) []byte { return file[(n+1)*ss : (n+2)*ss] }
	// FAT.
	fat := sec(0)
	for i := 0; i < 128; i++ {
		le.PutUint32(fat[4*i:], freeSect)
	}
	set := func(s, next uint32) { le.PutUint32(fat[4*s:], next) }
	set(0, 0xFFFFFFFD)
	set(1, endOfChain)
	set(2, endOfChain)
	set(3, 4)
	set(4, endOfChain)
	bigChain := []uint32{5, 7, 9, 11, 13, 6, 8, 10, 12, 14}
	for i, s := range bigChain {
		next := uint32(endOfChain)
		if i+1 < len(bigChain) {
			next = bigChain[i+1]
		}
		set(s, next)
	}
	// Ministrumień: minisektory 3,0,7,1.
	mfat := sec(2)
	for i := 0; i < 128; i++ {
		le.PutUint32(mfat[4*i:], freeSect)
	}
	miniChain := []uint32{3, 0, 7, 1}
	for i, m := range miniChain {
		next := uint32(endOfChain)
		if i+1 < len(miniChain) {
			next = miniChain[i+1]
		}
		le.PutUint32(mfat[4*m:], next)
	}
	ministream := append(bytes.Clone(sec(3)), sec(4)...)
	for i, m := range miniChain {
		lo := i * 64
		if lo >= len(small) {
			break
		}
		copy(ministream[int(m)*64:], small[lo:min(lo+64, len(small))])
	}
	copy(sec(3), ministream[:ss])
	copy(sec(4), ministream[ss:])
	for i, s := range bigChain {
		lo := i * ss
		if lo >= len(big) {
			break
		}
		copy(sec(int(s)), big[lo:min(lo+ss, len(big))])
	}
	// Katalog: root, mały strumień, duży strumień.
	dir := sec(1)
	ent := func(i int, typ byte, start uint32, size uint64) {
		e := dir[128*i : 128*(i+1)]
		e[66] = typ
		le.PutUint32(e[116:], start)
		le.PutUint64(e[120:], size)
	}
	ent(0, 5, 3, 1024)
	ent(1, 2, 3, uint64(len(small)))
	ent(2, 2, 5, uint64(len(big)))
	return file
}
