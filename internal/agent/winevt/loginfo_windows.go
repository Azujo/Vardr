//go:build windows

package winevt

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"

	"siem/internal/agent/logwatch"
)

var (
	procEvtOpenLog                  = wevtapi.NewProc("EvtOpenLog")
	procEvtGetLogInfo               = wevtapi.NewProc("EvtGetLogInfo")
	procEvtOpenChannelConfig        = wevtapi.NewProc("EvtOpenChannelConfig")
	procEvtGetChannelConfigProperty = wevtapi.NewProc("EvtGetChannelConfigProperty")
)

const (
	evtOpenChannelPath = 1

	// EVT_LOG_PROPERTY_ID
	evtLogFileSize           = 3
	evtLogNumberOfLogRecords = 5
	evtLogOldestRecordNumber = 6

	// EVT_CHANNEL_CONFIG_PROPERTY_ID
	evtChannelLoggingConfigRetention  = 6
	evtChannelLoggingConfigAutoBackup = 7
	evtChannelLoggingConfigMaxSize    = 8

	// EVT_VARIANT_TYPE
	evtVarTypeNull    = 0
	evtVarTypeBoolean = 13
	evtVarTypeUInt64  = 10
)

// evtVariant odpowiada strukturze EVT_VARIANT (8 B wartości, Count, Type).
type evtVariant struct {
	Value uint64
	Count uint32
	Type  uint32
}

// LogInfo odczytuje stan dziennika kanału: liczbę i numer najstarszego
// rekordu, rozmiar pliku oraz konfigurację (maks. rozmiar, nadpisywanie).
// Wymaga prawa odczytu dziennika (Security: konto SYSTEM lub administrator).
func LogInfo(channel string) (logwatch.Info, error) {
	var info logwatch.Info
	path, err := windows.UTF16PtrFromString(channel)
	if err != nil {
		return info, err
	}

	h, _, e := procEvtOpenLog.Call(0, uintptr(unsafe.Pointer(path)), evtOpenChannelPath)
	if h == 0 {
		return info, fmt.Errorf("EvtOpenLog %s: %w", channel, e)
	}
	defer evtClose(evtHandle(h))
	get := func(id uint32) (evtVariant, error) {
		var v [4]evtVariant // zapas na wypadek większej struktury
		var used uint32
		r, _, e := procEvtGetLogInfo.Call(h, uintptr(id), unsafe.Sizeof(v), uintptr(unsafe.Pointer(&v[0])), uintptr(unsafe.Pointer(&used)))
		if r == 0 {
			return evtVariant{}, e
		}
		return v[0], nil
	}
	for _, p := range []struct {
		id  uint32
		dst *uint64
	}{
		{evtLogNumberOfLogRecords, &info.Records},
		{evtLogOldestRecordNumber, &info.Oldest},
		{evtLogFileSize, &info.FileSize},
	} {
		v, err := get(p.id)
		if err != nil {
			return info, fmt.Errorf("EvtGetLogInfo %s: %w", channel, err)
		}
		if v.Type == evtVarTypeUInt64 {
			*p.dst = v.Value
		}
	}

	cfg, _, e := procEvtOpenChannelConfig.Call(0, uintptr(unsafe.Pointer(path)), 0)
	if cfg == 0 {
		return info, fmt.Errorf("EvtOpenChannelConfig %s: %w", channel, e)
	}
	defer evtClose(evtHandle(cfg))
	prop := func(id uint32) (evtVariant, error) {
		var v [4]evtVariant
		var used uint32
		r, _, e := procEvtGetChannelConfigProperty.Call(cfg, uintptr(id), 0, unsafe.Sizeof(v), uintptr(unsafe.Pointer(&v[0])), uintptr(unsafe.Pointer(&used)))
		if r == 0 {
			return evtVariant{}, e
		}
		return v[0], nil
	}
	if v, err := prop(evtChannelLoggingConfigMaxSize); err == nil && v.Type == evtVarTypeUInt64 {
		info.MaxSize = v.Value
	}
	if v, err := prop(evtChannelLoggingConfigRetention); err == nil && v.Type == evtVarTypeBoolean {
		info.Retention = uint32(v.Value) != 0
	}
	if v, err := prop(evtChannelLoggingConfigAutoBackup); err == nil && v.Type == evtVarTypeBoolean {
		info.AutoBackup = uint32(v.Value) != 0
	}
	return info, nil
}
