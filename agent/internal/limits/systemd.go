// SPDX-License-Identifier: AGPL-3.0-or-later

package limits

import "fmt"

// Properties: właściwości jednostki dla limitów (cpus – liczba procesorów;
// limit CPU w % całego komputera, CPUQuota – w % jednego procesora).
func Properties(l Limits, cpus int) []string {
	weight := map[string]string{PriorityNormal: "100", PriorityBelowNormal: "50", PriorityBackground: "1"}[l.Priority]
	if weight == "" {
		weight = "100"
	}
	quota, mem := "CPUQuota=", "MemoryMax=infinity"
	if l.CPUMaxPercent > 0 {
		q := l.CPUMaxPercent * float64(cpus)
		if q < 1 {
			q = 1
		}
		quota = fmt.Sprintf("CPUQuota=%.0f%%", q)
	}
	if l.MemoryHardMB > 0 {
		mem = fmt.Sprintf("MemoryMax=%dM", l.MemoryHardMB)
	}
	return []string{"CPUWeight=" + weight, "IOWeight=" + weight, quota, mem}
}
