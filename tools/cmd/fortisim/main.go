// Command fortisim to symulator dziennika FortiGate (FortiOS 7, format
// „default”: pary klucz=wartość) wysyłanego przez syslog do kolektora
// Heimdalla – do testów dekodera i reguł bez prawdziwego urządzenia.
//
//	go run ./tools/cmd/fortisim [-target 192.168.88.98:514] [-proto udp|tcp] [-scenario mix] [-count 20]
//
// Scenariusze:
//
//	traffic      ruch przepuszczony i zablokowany przez polityki (tło)
//	vpn-ok       udane logowania SSL VPN i zestawienie tunelu
//	vpn-brute    seria nieudanych logowań SSL VPN z jednego adresu (reguła „FortiGate – seria nieudanych logowań do VPN”)
//	vpn-spray    jak vpn-brute, ale na wiele różnych kont (credential stuffing)
//	admin-brute  nieudane logowania do panelu administracyjnego
//	utm          wpisy IPS i antywirusa
//	mix          wszystko po trochu (domyślnie)
package main

import (
	"flag"
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"strings"
	"time"
	_ "time/tzdata"
)

type sim struct {
	dev, devid, tz string
	loc            *time.Location
	header         string
	attacker       string
	n              int
}

func main() {
	target := flag.String("target", "192.168.88.98:514", "kolektor syslog (host:port)")
	proto := flag.String("proto", "udp", "udp albo tcp (ramki zakończone znakiem nowej linii)")
	scenario := flag.String("scenario", "mix", "traffic | portscan | sweep | vpn-ok | vpn-brute | vpn-spray | admin-brute | utm | mix")
	count := flag.Int("count", 0, "liczba wiadomości (0 – domyślna dla scenariusza)")
	rate := flag.Duration("every", 100*time.Millisecond, "odstęp między wiadomościami")
	dev := flag.String("devname", "FGT-HQ", "nazwa urządzenia (devname)")
	attacker := flag.String("attacker", "", "adres atakującego (domyślnie losowy z 203.0.113.0/24)")
	user := flag.String("user", "jkowalski", "konto w scenariuszu vpn-brute")
	header := flag.String("header", "bare", "nagłówek: bare (<PRI>date=…, domyślny FortiOS), rfc5424 albo rfc3164")
	tz := flag.String("tz", "Europe/Warsaw", "strefa czasowa urządzenia")
	dry := flag.Bool("dry", false, "tylko wypisz wiadomości, nie wysyłaj")
	flag.Parse()

	loc, err := time.LoadLocation(*tz)
	if err != nil {
		fail(err)
	}
	s := &sim{dev: *dev, devid: "FG100FTK2300" + fmt.Sprintf("%04d", rand.IntN(10000)), loc: loc, header: *header,
		attacker: *attacker}
	if s.attacker == "" {
		s.attacker = fmt.Sprintf("203.0.113.%d", 2+rand.IntN(250))
	}
	if s.tz = time.Now().In(loc).Format("-0700"); *header != "bare" && *header != "rfc5424" && *header != "rfc3164" {
		fail(fmt.Errorf("nieznany nagłówek %q", *header))
	}

	var lines []string
	switch *scenario {
	case "traffic":
		lines = s.repeat(nonzero(*count, 20), s.traffic)
	case "portscan":
		// Skanowanie portów: atakujący → jeden adres, kolejne porty, odrzucone.
		n := nonzero(*count, 25)
		for i := range n {
			lines = append(lines, s.deny("192.0.2.10", 20+i))
		}
	case "sweep":
		// Przeszukiwanie sieci: atakujący → kolejne adresy podsieci, port 445.
		n := nonzero(*count, 35)
		for i := range n {
			lines = append(lines, s.deny(fmt.Sprintf("10.10.20.%d", 1+i%254), 445))
		}
	case "vpn-ok":
		lines = s.vpnOK(nonzero(*count, 3))
	case "vpn-brute":
		lines = s.repeat(nonzero(*count, 12), func() string { return s.vpnFail(*user) })
	case "vpn-spray":
		lines = s.repeat(nonzero(*count, 12), func() string { return s.vpnFail(users[rand.IntN(len(users))]) })
	case "admin-brute":
		lines = s.repeat(nonzero(*count, 6), s.adminFail)
	case "utm":
		lines = s.repeat(nonzero(*count, 4), s.utm)
	case "mix":
		lines = append(lines, s.repeat(10, s.traffic)...)
		lines = append(lines, s.vpnOK(2)...)
		lines = append(lines, s.repeat(12, func() string { return s.vpnFail("jkowalski") })...)
		lines = append(lines, s.repeat(6, s.adminFail)...)
		lines = append(lines, s.repeat(3, s.utm)...)
	default:
		fail(fmt.Errorf("nieznany scenariusz %q", *scenario))
	}

	if *dry {
		for _, l := range lines {
			fmt.Println(l)
		}
		return
	}
	conn, err := net.DialTimeout(*proto, *target, 5*time.Second)
	if err != nil {
		fail(err)
	}
	defer conn.Close()
	for i, l := range lines {
		msg := l
		if *proto == "tcp" {
			msg += "\n"
		}
		if _, err := conn.Write([]byte(msg)); err != nil {
			fail(fmt.Errorf("wiadomość %d: %w", i+1, err))
		}
		time.Sleep(*rate)
	}
	fmt.Printf("wysłano %d wiadomości (%s) do %s/%s, atakujący %s\n", len(lines), *scenario, *target, *proto, s.attacker)
}

var users = []string{"jkowalski", "anowak", "pwisniewski", "kwojcik", "mkaminska", "admin", "test", "backup", "biuro", "ksiegowosc"}

func (s *sim) repeat(n int, f func() string) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = f()
	}
	return out
}

// line składa wiadomość: pola wspólne FortiOS + pola wpisu.
func (s *sim) line(pri int, logid, typ, subtype, level string, kv ...string) string {
	s.n++
	now := time.Now().In(s.loc)
	var b strings.Builder
	fmt.Fprintf(&b, `date=%s time=%s devname=%q devid=%q eventtime=%d tz=%q logid=%q type=%q subtype=%q level=%q vd="root"`,
		now.Format("2006-01-02"), now.Format("15:04:05"), s.dev, s.devid, now.UnixNano(), s.tz, logid, typ, subtype, level)
	for i := 0; i+1 < len(kv); i += 2 {
		v := kv[i+1]
		if strings.ContainsAny(v, " \"=") || v == "" || !numeric(v) && kv[i] != "srcip" && kv[i] != "dstip" && kv[i] != "remip" {
			v = fmt.Sprintf("%q", v)
		}
		fmt.Fprintf(&b, " %s=%s", kv[i], v)
	}
	switch s.header {
	case "rfc5424":
		return fmt.Sprintf("<%d>1 %s %s - - - - %s", pri, now.Format(time.RFC3339), s.dev, b.String())
	case "rfc3164":
		return fmt.Sprintf("<%d>%s %s %s", pri, now.Format(time.Stamp), s.dev, b.String())
	}
	return fmt.Sprintf("<%d>%s", pri, b.String())
}

func (s *sim) traffic() string {
	src := fmt.Sprintf("192.168.1.%d", 10+rand.IntN(200))
	dst := []string{"8.8.8.8", "1.1.1.1", "142.250.186.78", "151.101.1.69", "20.42.73.29"}[rand.IntN(5)]
	svc, port, proto := "HTTPS", "443", "6"
	if rand.IntN(4) == 0 {
		svc, port, proto = "DNS", "53", "17"
	}
	action, policy := "accept", "1"
	if rand.IntN(5) == 0 {
		src, dst, action, policy = s.attacker, "192.0.2.10", "deny", "0"
		svc, port, proto = "RDP", "3389", "6"
	}
	return s.line(189, "0000000013", "traffic", "forward", "notice",
		"srcip", src, "srcport", fmt.Sprint(1024+rand.IntN(60000)), "srcintf", "port2", "srcintfrole", "lan",
		"dstip", dst, "dstport", port, "dstintf", "wan1", "dstintfrole", "wan", "sessionid", fmt.Sprint(100000+s.n),
		"proto", proto, "action", action, "policyid", policy, "policytype", "policy", "service", svc,
		"duration", fmt.Sprint(rand.IntN(300)), "sentbyte", fmt.Sprint(rand.IntN(90000)), "rcvdbyte", fmt.Sprint(rand.IntN(900000)))
}

// deny: odrzucone połączenie atakującego (skanowanie).
func (s *sim) deny(dst string, port int) string {
	return s.line(189, "0000000013", "traffic", "forward", "notice",
		"srcip", s.attacker, "srcport", fmt.Sprint(40000+rand.IntN(20000)), "srcintf", "wan1", "srcintfrole", "wan",
		"dstip", dst, "dstport", fmt.Sprint(port), "dstintf", "port2", "dstintfrole", "lan", "sessionid", fmt.Sprint(100000+s.n),
		"proto", "6", "action", "deny", "policyid", "0", "policytype", "policy", "service", fmt.Sprintf("tcp/%d", port),
		"duration", "0", "sentbyte", "0", "rcvdbyte", "0")
}

func (s *sim) vpnOK(n int) []string {
	var out []string
	for range n {
		u := users[rand.IntN(5)]
		ip := fmt.Sprintf("198.51.100.%d", 2+rand.IntN(250))
		out = append(out,
			s.line(189, "0101039947", "event", "vpn", "information", "logdesc", "SSL VPN tunnel up", "action", "tunnel-up",
				"tunneltype", "ssl-tunnel", "tunnelid", fmt.Sprint(1000+s.n), "remip", ip, "tunnelip", fmt.Sprintf("10.212.134.%d", 200+rand.IntN(50)),
				"user", u, "group", "VPN-Users", "dst_host", "N/A", "reason", "tunnel established", "msg", "SSL tunnel established"))
	}
	return out
}

func (s *sim) vpnFail(user string) string {
	return s.line(189, "0101039426", "event", "vpn", "alert", "logdesc", "SSL VPN login fail", "action", "ssl-login-fail",
		"tunneltype", "ssl-web", "tunnelid", "0", "remip", s.attacker, "user", user, "group", "N/A", "dst_host", "N/A",
		"reason", "sslvpn_login_permission_denied", "msg", "SSL user failed to logged in")
}

func (s *sim) adminFail() string {
	u := []string{"admin", "fortinet", "root", "administrator"}[rand.IntN(4)]
	return s.line(185, "0100032002", "event", "system", "alert", "logdesc", "Admin login failed", "sn", "0", "user", u,
		"ui", fmt.Sprintf("https(%s)", s.attacker), "method", "https", "srcip", s.attacker, "dstip", "192.0.2.1",
		"action", "login", "status", "failed", "reason", "passwd_invalid",
		"msg", fmt.Sprintf("Administrator %s login failed from https(%s) because of invalid password", u, s.attacker))
}

func (s *sim) utm() string {
	if rand.IntN(2) == 0 {
		return s.line(185, "0419016384", "utm", "ips", "alert", "eventtype", "signature", "severity", "critical",
			"srcip", s.attacker, "srcport", fmt.Sprint(1024+rand.IntN(60000)), "dstip", "192.0.2.10", "dstport", "443",
			"proto", "6", "action", "dropped", "attack", "Apache.Log4j.Error.Log.Remote.Code.Execution", "attackid", "51006",
			"ref", "http://www.fortinet.com/ids/VID51006", "msg", "applications3: Apache.Log4j.Error.Log.Remote.Code.Execution")
	}
	return s.line(185, "0211008192", "utm", "virus", "warning", "eventtype", "infected", "srcip", "185.199.108.153",
		"dstip", fmt.Sprintf("192.168.1.%d", 10+rand.IntN(200)), "proto", "6", "service", "HTTPS", "action", "blocked",
		"filename", "invoice.pdf.exe", "virus", "W32/Agent.ABCD!tr", "dtype", "av-engine",
		"url", "https://downloads.example.net/invoice.pdf.exe", "msg", "File is infected.")
}

func numeric(v string) bool {
	for _, c := range v {
		if c < '0' || c > '9' {
			return false
		}
	}
	return v != ""
}

func nonzero(v, def int) int {
	if v > 0 {
		return v
	}
	return def
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "fortisim:", err)
	os.Exit(1)
}
