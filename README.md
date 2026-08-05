# llp-fritzbox-sperrliste

Kleines Web-Tool zum Sperren von Rufnummern in der FRITZ!Box, gedacht zum Einbinden
per `<iframe>` in eine bereits zugriffsgeschützte Webseite.

* **Rufnummer sperren** – Eingabemaske mit Rufnummer und optionaler Bezeichnung.
* **Sperrliste anzeigen** – alle aktuell gesperrten Rufnummern, mit Entsperr-Schaltfläche.

## Aufbau

| Teil | Ort |
|---|---|
| Oberfläche | `index.html`, statisch über GitHub Pages |
| Backend | Supabase Edge Function `fritzbox-sperrliste` (Projekt `llp-schuldaten`) |
| FRITZ!Box | TR-064, Dienst `X_AVM-DE_OnTel` |

Die Oberfläche kann die FRITZ!Box nicht direkt ansprechen (kein CORS, SOAP mit
Digest-Authentifizierung), deshalb liegt die Logik in der Edge Function. Diese nutzt die
offiziell dokumentierten Aktionen `GetCallBarringList`, `SetCallBarringEntry` und
`DeleteCallBarringEntryUID`.

## Voraussetzungen an der FRITZ!Box

1. **Heimnetz → Netzwerk → Netzwerkeinstellungen:** „Zugriff für Anwendungen zulassen" aktiviert.
2. Ein **FRITZ!Box-Benutzer mit dem Recht „Telefonie"** (System → FRITZ!Box-Benutzer).
3. Die TR-064-Schnittstelle muss über den Reverse Proxy **per TLS** erreichbar sein –
   die Box beantwortet Telefonie-Aktionen sonst mit `504 SSL needed`. Der Proxy-Upstream
   muss also auf `https://<Box-IP>:49443` zeigen (nicht auf Port 49000), unter Akzeptanz
   des selbstsignierten Zertifikats der Box.

## Secrets der Edge Function

| Name | Bedeutung |
|---|---|
| `FRITZBOX_URL` | Basis-URL der TR-064-Schnittstelle, z. B. `https://fritzbox.example.org/tr064` |
| `FRITZBOX_USER` | FRITZ!Box-Benutzer mit dem Recht „Telefonie" |
| `FRITZBOX_PASSWORD` | dessen Kennwort |
| `TOOL_ACCESS_KEY` | gemeinsames Geheimnis; ohne passenden Schlüssel antwortet die Funktion mit 403 |

## Einbinden

Der Zugriffsschlüssel wird als Parameter an die Seite übergeben und von dort an die
Edge Function weitergereicht:

```html
<iframe src="https://stephankurz.github.io/llp-fritzbox-sperrliste/?key=DEIN_SCHLUESSEL"
        style="width:100%;height:700px;border:0"></iframe>
```

Der Schlüssel steht damit im Quelltext der einbettenden Seite – er schützt die Funktion
davor, allein durch Erraten der Supabase-URL nutzbar zu sein, ersetzt aber keinen Login.
Die Zugriffskontrolle bleibt Aufgabe der einbettenden Webseite.
