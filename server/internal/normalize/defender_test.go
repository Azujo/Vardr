// SPDX-License-Identifier: AGPL-3.0-or-later

package normalize

import "testing"

// Wykrycie EICAR przez Microsoft Defender (1116) – tak jak zapisuje je Windows 11.
const def1116 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender' Guid='{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}'/><EventID>1116</EventID><Version>0</Version><Level>3</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-10-19T12:40:01.250Z'/><EventRecordID>812</EventRecordID><Correlation/><Execution ProcessID='3456' ThreadID='7788'/><Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>DESKTOP-3P8VS81.azujo.centrala</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='Product Version'>4.18.25070.5</Data><Data Name='Detection ID'>{2F1A5C0E-1B11-4C66-A0D5-7E2A2C9F9A10}</Data><Data Name='Threat ID'>2147519003</Data><Data Name='Threat Name'>Virus:DOS/EICAR_Test_File</Data><Data Name='Severity ID'>5</Data><Data Name='Severity Name'>Severe</Data><Data Name='Category ID'>42</Data><Data Name='Category Name'>Virus</Data><Data Name='Process Name'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='Detection User'>AZUJO\heimdall-lab</Data><Data Name='Path'>file:_C:\Windows\Temp\vardr-test\eicar.com</Data><Data Name='Action Name'>Not Applicable</Data><Data Name='Error Description'>-</Data></EventData></Event>`

// Dodane wykluczenie ścieżki (5007).
const def5007 = `<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Windows Defender' Guid='{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}'/><EventID>5007</EventID><Version>0</Version><Level>4</Level><Task>0</Task><Opcode>0</Opcode><Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='2026-10-19T12:41:00Z'/><EventRecordID>813</EventRecordID><Correlation/><Execution ProcessID='3456' ThreadID='7788'/><Channel>Microsoft-Windows-Windows Defender/Operational</Channel><Computer>PC01.lab.local</Computer><Security UserID='S-1-5-18'/></System><EventData><Data Name='Product Name'>Microsoft Defender Antivirus</Data><Data Name='Product Version'>4.18.25070.5</Data><Data Name='Old Value'></Data><Data Name='New Value'>HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public = 0x0</Data></EventData></Event>`

func TestDefenderEvents(t *testing.T) {
	e, err := Event(ev("wineventlog:Microsoft-Windows-Windows Defender/Operational", def1116), "agt-1", ingested)
	if err != nil {
		t.Fatal(err)
	}
	if e.Dataset != "windows.defender" || e.Action != "malware-detected" || e.UserName != "heimdall-lab" || e.UserDomain != "AZUJO" ||
		e.ProcessName != `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` || e.Fields["Threat Name"] != "Virus:DOS/EICAR_Test_File" ||
		e.Message != `Virus:DOS/EICAR_Test_File – Severe – Virus – Not Applicable – file:_C:\Windows\Temp\vardr-test\eicar.com` {
		t.Fatalf("1116: %+v", e)
	}
	e, err = Event(ev("wineventlog:Microsoft-Windows-Windows Defender/Operational", def5007), "agt-1", ingested)
	if err != nil {
		t.Fatal(err)
	}
	if e.Action != "config-changed" || e.Message != `zmiana ustawienia: HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\Public = 0x0` {
		t.Fatalf("5007: %+v", e)
	}
}

func TestDefenderErrorOnlyOnFailure(t *testing.T) {
	ok := map[string]string{"Threat Name": "X", "Error Code": "0x00000000", "Error Description": "Operacja ukończona pomyślnie."}
	if m := defenderMessage(ok); m != "X" {
		t.Fatalf("sukces: %q", m)
	}
	ok["Error Code"] = "0x80508023"
	ok["Error Description"] = "Nie można odnaleźć programu"
	if m := defenderMessage(ok); m != "X – Nie można odnaleźć programu" {
		t.Fatalf("błąd: %q", m)
	}
}
