## Toxicframe

Guten morgen, mein Name ist Wim Bonis. Ich bin bei der Stylite AG für Technik und Netzwerke zuständig.

Heute spreche ich über #toxicframe.

Wir haben einen interessanten Bug gefunden: Dateitransfers brechen immer bei 49% ab

SLIDE 1

Ein Kunde berichtet, dass seine Dateiübertragung immer bei 49% abbricht. über ein VPN zu einem Windows Server. 
Was Neu war: Ein Netgate SG-2100 mit pfSense wurde vor ein paar Wochen installiert.

Das Problem, war immer zu 100% nachvollziehbar. Immer bei 49% einer bestimmten Datei.

Der Kunde hat tausende andere Dateien erfolgreich übertragen - nur diese eine Datei bricht immer ab.

Die Datei ist knapp 200MB groß. und kommt aus einer Microsoft Office Installation.

SLIDE 2

Wir haben alle üblichen Verdächtigen überprüft:
- MTU, Fragmentierung, VPN-Protokolle
- Virenscanner und Deep Packet Inspection
- Hardware-Offloading der Firewall

auch das war es nicht

SLIDE 3

Wir haben uns die datei bei 49% angeschaut und konnten das Problem auf einen einzigen 1 kilobyte großen Block eingegrenzt. Dieses "toxische Paket" habe wir isoliert.

SLIDE 4

Wir haben festgestellt, das das Problem unabhängig von Protokoll ist.

Auch ein Transfer über http bricht ab.
Auch ohne das der WAN Port beteiligt ist. 
Auch beim routing zwichen 2 VLANs bricht es ab.

SLIDE 5

Die Hardware is eine Netgate SG-2100 mit pfSense.

Die Architektur sieht so aus:

Es gibt einen ARM-Prozessor, einen WAN-Port mit 1 Gigabit , und ein interner Marvell Switch mit 2.5 Gigabit im Uplink.
Das Problem tritt nur auf, wenn der Switch-Pfad beteiligt ist.

SLIDE 6

ein TCP-Dump zeigt: Das Paket verschwindet im Switch!

Es wird von der CPU gesendet, erreicht aber den Client nie. Das  Paket wird zwischen CPU und Switch gedroppt.
Wo genau ist noch nicht klar.

SLIDE 7
Das Problem ist nicht neu. Wir haben einen auf Reddit einen Post aus 2020 gefunden: "Weirdest Issue Ever" - exakt dieselben Symptome. Damals auch ohne Lösung.

SLIDE 8

Wir haben Netgate kontaktiert.

Netgate hat den Bug bestätigt und konnte ihn reproduzieren.

Es gab noch keien Antwort, ob es einen Fix geben wird.

SLIDE 9

Das Paket enthält ein 14-Byte-Pattern, das sich 39-mal wiederholt, weitere Test zeigen das das Packet auch noch kleiner sein kann.ir haben es auch nur mit einem kleineren 300byte packet mit der Sequenz versucht, und auch das triggert den Fehler.

SLIDE 10

Wir haben auch andere Hardware getestet:

GL-iNet hat einen ähnliche Router mit derselben CPU und demselben Switch Chip, allerdings nur mit einem gigabit Uplink.

Hier konnten wir den Bug mit OpenWRT nicht sehen.

SLIDE 11

Was vermuten wir nun?
Liegt es am ASIC, ist es ein Timing-Issue oder elektrisches Problem?
Ich denke es ist ein Bug in der Hardware. Oder zumindest in der Anbindung der Hardware.
Ob der Hersteller es Fixen kann ist unklar.

Als workaroud könnte man den Internen Switch umgehen und den WAN Port mit VLANs nutzen.

SLIDE 12

Ihr findet mich am OpenWRT-Tisch. In Halle H
Wenn ihr Ideen oder Hinweise habt, meldet euch.
Ich hab die Hardware dabei.
Wenn ihr selbst eine Router mit Marvell Switch habt, testet bitte die böse Datei.


Vielen Dank!