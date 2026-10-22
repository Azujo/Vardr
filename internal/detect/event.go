// SPDX-License-Identifier: AGPL-3.0-or-later

package detect

import (
	"strconv"
	"strings"

	"siem/internal/model"
)

// Event to zdarzenie oceniane przez reguły.
type Event struct {
	*model.Event
}

// aliases: pola Sigmy, które w różnych źródłach nazywają się inaczej
// (np. tworzenie procesu: Sysmon 1 – Image, Security 4688 – NewProcessName).
var aliases = map[string][]string{
	"Image":             {"Image", "NewProcessName"},
	"ParentImage":       {"ParentImage", "ParentProcessName"},
	"User":              {"User", "SubjectUserName"},
	"IntegrityLevel":    {"IntegrityLevel", "MandatoryLabel"},
	"SourceIp":          {"SourceIp", "IpAddress"},
	"IpAddress":         {"IpAddress", "SourceIp"},
	"WorkstationName":   {"WorkstationName", "Workstation"},
	"ScriptBlockText":   {"ScriptBlockText"},
	"ServiceFileName":   {"ServiceFileName", "ImagePath"},
	"TargetObject":      {"TargetObject", "ObjectName"},
	"QueryName":         {"QueryName"},
	"DestinationIp":     {"DestinationIp", "DestAddress"},
	"DestinationPort":   {"DestinationPort", "DestPort"},
	"TargetFilename":    {"TargetFilename"},
	"CurrentDirectory":  {"CurrentDirectory"},
	"OriginalFileName":  {"OriginalFileName"},
	"TargetUserName":    {"TargetUserName"},
	"SubjectUserName":   {"SubjectUserName"},
	"MemberName":        {"MemberName"},
	"MemberSid":         {"MemberSid"},
	"TargetUserSid":     {"TargetUserSid"},
	"LogonType":         {"LogonType"},
	"Status":            {"Status"},
	"SubStatus":         {"SubStatus"},
	"ServiceName":       {"ServiceName"},
	"TaskName":          {"TaskName"},
	"CommandLine":       {"CommandLine"},
	"ParentCommandLine": {"ParentCommandLine"},
}

// Get zwraca wartość pola: nazwy Sigmy (EventID, Channel, Provider_Name,
// Computer, pola EventData), nazwy ECS (event.code, user.name…) i aliasy.
func (e Event) Get(field string) (string, bool) {
	switch field {
	case "EventID", "event.code", "event_code":
		return strconv.FormatUint(uint64(e.Code), 10), true
	case "Channel", "winlog.channel":
		v, ok := e.Fields["winlog.channel"]
		return v, ok
	case "Provider_Name", "event.provider":
		return e.Provider, e.Provider != ""
	case "Computer", "host.name", "Hostname":
		return e.HostName, e.HostName != ""
	case "event.dataset":
		return e.Dataset, true
	case "event.action":
		return e.Action, e.Action != ""
	case "event.outcome":
		return e.Outcome, e.Outcome != ""
	case "user.name":
		return e.UserName, e.UserName != ""
	case "user.domain":
		return e.UserDomain, e.UserDomain != ""
	case "user.identity":
		return e.Identity, e.Identity != ""
	case "source.ip":
		return e.SourceIP, e.SourceIP != ""
	case "process.name":
		return e.ProcessName, e.ProcessName != ""
	case "process.command_line":
		return e.CommandLine, e.CommandLine != ""
	case "agent.id":
		return e.AgentID, true
	case "message":
		return e.Message, e.Message != ""
	}
	names := aliases[field]
	if names == nil {
		names = []string{field}
	}
	for _, n := range names {
		if v, ok := e.Fields[n]; ok {
			return v, true
		}
	}
	// Ostatnia próba: nazwa pola bez względu na wielkość liter.
	for k, v := range e.Fields {
		if strings.EqualFold(k, field) {
			return v, true
		}
	}
	return "", false
}
