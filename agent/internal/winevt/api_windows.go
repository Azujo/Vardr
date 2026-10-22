// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build windows

package winevt

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// Minimalne wiązania do wevtapi.dll (Windows Event Log API).
var (
	wevtapi               = windows.NewLazySystemDLL("wevtapi.dll")
	procEvtSubscribe      = wevtapi.NewProc("EvtSubscribe")
	procEvtNext           = wevtapi.NewProc("EvtNext")
	procEvtRender         = wevtapi.NewProc("EvtRender")
	procEvtCreateBookmark = wevtapi.NewProc("EvtCreateBookmark")
	procEvtClose          = wevtapi.NewProc("EvtClose")
)

type evtHandle uintptr

const (
	evtSubscribeToFutureEvents      = 1
	evtSubscribeStartAtOldestRecord = 2
	evtSubscribeStartAfterBookmark  = 3

	evtRenderEventXML = 1

	errorInsufficientBuffer  = windows.Errno(122)
	errorNoMoreItems         = windows.Errno(259)
	errorEvtChannelNotFound  = windows.Errno(15007)
	errorEvtQueryResultStale = windows.Errno(15011)
	errorEvtInvalidQuery     = windows.Errno(15001)
	errorAccessDenied        = windows.Errno(5)
	errorInvalidOperation    = windows.Errno(4317)
)

func evtSubscribe(signal windows.Handle, channel, query string, bookmark evtHandle, flags uint32) (evtHandle, error) {
	ch, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return 0, err
	}
	q, err := windows.UTF16PtrFromString(query)
	if err != nil {
		return 0, err
	}
	r, _, e := procEvtSubscribe.Call(0, uintptr(signal),
		uintptr(unsafe.Pointer(ch)), uintptr(unsafe.Pointer(q)),
		uintptr(bookmark), 0, 0, uintptr(flags))
	if r == 0 {
		return 0, e
	}
	return evtHandle(r), nil
}

// evtNext pobiera do len(out) zdarzeń bez czekania. Zwraca liczbę uchwytów.
func evtNext(sub evtHandle, out []evtHandle) (int, error) {
	var returned uint32
	r, _, e := procEvtNext.Call(uintptr(sub), uintptr(len(out)),
		uintptr(unsafe.Pointer(&out[0])), 0, 0, uintptr(unsafe.Pointer(&returned)))
	if r == 0 {
		return 0, e
	}
	return int(returned), nil
}

// evtRenderXML renderuje zdarzenie jako XML, wykorzystując i w razie potrzeby
// powiększając bufor wielokrotnego użytku.
func evtRenderXML(h evtHandle, buf *[]uint16) (string, error) {
	for {
		var used, props uint32
		var ptr uintptr
		if len(*buf) > 0 {
			ptr = uintptr(unsafe.Pointer(&(*buf)[0]))
		}
		r, _, e := procEvtRender.Call(0, uintptr(h), evtRenderEventXML,
			uintptr(len(*buf)*2), ptr,
			uintptr(unsafe.Pointer(&used)), uintptr(unsafe.Pointer(&props)))
		if r != 0 {
			return windows.UTF16ToString((*buf)[:used/2]), nil
		}
		if e != errorInsufficientBuffer {
			return "", e
		}
		*buf = make([]uint16, used/2+256)
	}
}

func evtCreateBookmark(xml string) (evtHandle, error) {
	p, err := windows.UTF16PtrFromString(xml)
	if err != nil {
		return 0, err
	}
	r, _, e := procEvtCreateBookmark.Call(uintptr(unsafe.Pointer(p)))
	if r == 0 {
		return 0, e
	}
	return evtHandle(r), nil
}

func evtClose(h evtHandle) {
	if h != 0 {
		procEvtClose.Call(uintptr(h))
	}
}
