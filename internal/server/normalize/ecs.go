package normalize

import (
	"strings"

	"siem/internal/server/model"
)

type rule struct {
	action string
	// targetUser: użytkownik zdarzenia to Target* (np. logowanie), a nie Subject*.
	targetUser bool
	outcome    string // wymuszony wynik (np. 4625 zawsze failure)
}

// Mapowanie Event ID → event.action dla kanałów z załącznika B roadmapy.
var securityRules = map[uint32]rule{
	4624: {"logged-in", true, "success"},
	4625: {"logon-failed", true, "failure"},
	4634: {"logged-out", true, ""},
	4647: {"logged-out", true, ""},
	4648: {"logged-in-explicit", false, ""},
	4672: {"logged-in-special", false, ""},
	4688: {"process-created", false, ""},
	4697: {"service-installed", false, ""},
	4698: {"scheduled-task-created", false, ""},
	4702: {"scheduled-task-updated", false, ""},
	4719: {"audit-policy-changed", false, ""},
	1102: {"audit-log-cleared", false, ""},
	4720: {"user-account-created", false, ""},
	4722: {"user-account-enabled", false, ""},
	4723: {"password-change-attempted", false, ""},
	4724: {"password-reset", false, ""},
	4725: {"user-account-disabled", false, ""},
	4726: {"user-account-deleted", false, ""},
	4738: {"user-account-changed", false, ""},
	4740: {"user-account-locked-out", true, ""},
	4767: {"user-account-unlocked", false, ""},
	4728: {"added-member-to-group", false, ""},
	4732: {"added-member-to-group", false, ""},
	4756: {"added-member-to-group", false, ""},
	4729: {"removed-member-from-group", false, ""},
	4733: {"removed-member-from-group", false, ""},
	4757: {"removed-member-from-group", false, ""},
	4768: {"kerberos-tgt-requested", true, ""},
	4769: {"kerberos-service-ticket-requested", true, ""},
	4771: {"kerberos-preauth-failed", true, "failure"},
	4776: {"credential-validated", true, ""},
}

var otherRules = map[string]map[uint32]rule{
	"windows.system": {
		7036: {action: "service-state-changed"},
		7040: {action: "service-start-type-changed"},
		7045: {action: "service-installed"},
	},
	"windows.powershell": {
		4104: {action: "script-block-logged"},
	},
	"windows.sysmon": {
		1:  {action: "process-created"},
		3:  {action: "network-connection"},
		11: {action: "file-created"},
		13: {action: "registry-value-set"},
		22: {action: "dns-query"},
	},
}

// applyECS uzupełnia pola wspólne (akcja, wynik, użytkownik, IP, proces).
func applyECS(e *model.Event) {
	f := e.Fields
	var r rule
	var ok bool
	if e.Dataset == "windows.security" {
		r, ok = securityRules[e.Code]
	} else {
		r, ok = otherRules[e.Dataset][e.Code]
	}
	if ok {
		e.Action = r.action
		if r.outcome != "" {
			e.Outcome = r.outcome
		}
	}

	// Użytkownik.
	if r.targetUser {
		e.UserName, e.UserDomain = clean(f["TargetUserName"]), clean(f["TargetDomainName"])
	}
	if e.UserName == "" {
		e.UserName, e.UserDomain = clean(f["SubjectUserName"]), clean(f["SubjectDomainName"])
	}
	if e.UserName == "" && f["User"] != "" { // Sysmon: "DOMENA\użytkownik"
		if dom, user, found := strings.Cut(f["User"], `\`); found {
			e.UserName, e.UserDomain = user, dom
		} else {
			e.UserName = f["User"]
		}
	}

	// Adres źródłowy.
	for _, k := range []string{"IpAddress", "SourceIp", "ClientAddress"} {
		if ip := normalizeIP(f[k]); ip != "" {
			e.SourceIP = ip
			break
		}
	}

	// Proces.
	for _, k := range []string{"NewProcessName", "Image", "ProcessName", "ImagePath", "ServiceFileName"} {
		if p := clean(f[k]); p != "" {
			e.ProcessName = p
			break
		}
	}
	e.CommandLine = clean(f["CommandLine"])

	// Wyniki zależne od statusu.
	if e.Dataset == "windows.security" && e.Code == 4776 {
		if s := strings.ToLower(clean(f["Status"])); s == "0x0" {
			e.Outcome = "success"
		} else if s != "" {
			e.Outcome = "failure"
		}
	}
	if e.Dataset == "windows.powershell" && e.Code == 4104 && e.Message == "" {
		e.Message = f["ScriptBlockText"]
	}
	if e.Dataset == "windows.system" && e.Code == 7036 && e.Message == "" {
		e.Message = strings.TrimSpace(f["param1"] + " " + f["param2"])
	}
}
