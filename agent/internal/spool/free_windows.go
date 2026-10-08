package spool

import "golang.org/x/sys/windows"

// DiskFree zwraca wolne miejsce na dysku katalogu (dla bieżącego użytkownika).
func DiskFree(dir string) (uint64, error) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, err
	}
	var free, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(p, &free, &total, &totalFree); err != nil {
		return 0, err
	}
	return free, nil
}
