# Native Hermès / Watch6,18 / watchOS 26.6.1 (23U95) — onderzoeks- en testmatrix

**Exact einddoel:** de originele Apple Hermès-system FaceBundles verschijnen in de **Apple ClockFace/Carousel-galerij**, blijven daar wanneer HermesEnabler gesloten is en zijn selecteerbaar na een herstart. Noch een eigen SwiftUI FaceView, noch een `.watchface`-ZIP, noch een XPC-verbinding alleen is bewijs van succes.

## 1. Wat het systeem echt doet (offline vastgesteld)

Deze bewijsstappen komen uit de **originele Watch6,18/23U95** Apple-firmware, gevalideerde Mach-O SHA-256-checks en disassemblage in [PR #18](https://github.com/mkalter/TESTAPP/pull/18) en [PR #19](https://github.com/mkalter/TESTAPP/pull/19). Sommige aanvullende uitspraken over JSON/migratie zijn afgeleid uit afzonderlijk **iOS 26.1**-materiaal; die moeten op Watch 23U95 nog onafhankelijk worden bevestigd.

1. **Aanwezigheid** — Zeus (`NTKPoodleFace`, Circulaire) en `NTKHermes2025FaceBundle` zijn onderdeel van de onderzochte originele firmware. Het zijn ondertekende systeemimplementaties en geen vrij bewerkbare appbestanden.
2. **Gallerij-registratie** — `NTKFaceBundleManager.enumerateFaceBundlesOnDevice:` slaat FaceBundles over wanneer `faceClass.isRestrictedForDevice:` waar is. `NTKGalleryCollection` filtert hardware-specifieke bundles apart.
3. **FaceBundle-resolutie** — bij reguliere bundle-ID-lookup wordt `isRestrictedForDevice:` opnieuw gecheckt. De enkele migratie/snapshot-uitzondering die in iOS 26.1 zichtbaar is, is **niet** hetzelfde als een recht om de Watch-galerij te wijzigen.
4. **Opslaan** — op 23U95 bevat `NTKDCollectionStore._queue_addFace:forUUID:` de echte `addUUID:withFaceStyle:` plus resourceopslag. Deze specifieke functie roept `_NTKCanAddWatchFace` niet direct aan; dat zegt niets over haar aanroepers of de latere renderer.
5. **Library cleanup** — op 23U95 controleert `_removeUnavailableFacesFromStore:` bij het onderzochte directe callsite `_NTKFaceStyleIsAvailable(style,device)` en verwijdert vervolgens met `removeFaceForUUID:`. Dit is **niet** de per-FaceBundle `isRestrictedForDevice:`-controle. Hypothese: een stijl-44-record zou deze ene cleanup kunnen overleven. Niet geverifieerd op een echte Watch.
6. **Andere opslagcontrole** — `NTKDSyncController._queue_validateLibraryFaces` gebruikt `flushAndComputeValidationHashWithObserverCallback:`. Dit is niet hetzelfde als de add-availability predicate, en de hashfunctie kan zelf intern meer controleren.
7. **Authorization** — Apple daemons bezitten aparte FaceSupport- en collection-entitlements. De gebruikelijke sandbox `mach-lookup` allowlist van 23U95 bevat wel `com.apple.ClockKit.CLKWatchFaceLibrary`, niet alle library- en replication-service-namen. Een XPC-listener die `YES` retourneert verleent geen clienttoegang.
8. **Device gate** — gemeten Ultra 1: `deviceCategory=4`, `collectionType=9`, `NTKShowHardwareSpecificFaces=false`. De volledige oorspronkelijke Zeus Poodle-class functie geeft hiermee `restricted=true`. Schrijven naar een willekeurige plist verandert de Apple-ondertekende klasse niet.

## 2. Concrete testen die nu in de Watch-app staan

De nieuwe, **geïsoleerde** `Native Face Lab` is rechtstreeks vanuit de Watch UI bereikbaar, zelfs wanneer er nog geen MobileGestalt-back-up bestaat. Iedere test heeft een eigen knop, een apart log en overdracht naar **HermesEnabler → Watch Logs** op de iPhone. Er wordt niet naar Apple's systeembestanden geschreven en er worden geen XPC-methoden aangeroepen.

| Test | Meet feitelijk | Positieve uitkomst bewijst | Betekenis bij blokkade |
|---|---|---|---|
| **T1 Mach-policy** | `sandbox_check(pid,"mach-lookup",GLOBAL_NAME=2,service)` voor ClockKit en exacte gallery-broker, collection, replication, relay, FaceSupport, Carousel en MG-diensten | Het **effectieve** sandboxbeleid van onze app is voor deze naam niet direct afwijzend | Zonder toegestane mach-lookup is direct benaderen van die service onaannemelijk |
| **T2 Bootstrap-lookup** | Alleen `bootstrap_look_up` met eigen bootstrapport; verkregen poorten direct vrijgeven | De named Mach service kan vanuit onze app worden gevonden | Kan een namespace-, ontbrekende-service- of sandboxprobleem zijn; de numeric returncode onderscheidt die, niet alleen een preflight |
| **T3 Store-/capability-locaties** | Alleen `lstat`, `open(O_RDONLY|O_NOFOLLOW)` en policycheck voor `NanoTimeKit`, `FaceSupport`, Preferences, `NanoRegistry`, `DeviceRegistry`, `pairedsync`, MG en eigen control | Concreet bestaand pad en echte **read** toegankelijkheid; write is uitsluitend *preflight* | Mogelijk verkeerde/user-contextspecifieke locatie of expliciete bestandsrestrictie. Niet blind een pad schrijven |
| **T4 Originele FaceBundles** | Bestaande on-disk systeemfolders `NTKZeusFaceBundle`, `NTKHermes2025FaceBundle`, NanoTimeKit en nanotimekitd; geen `dlopen` | Welke originele firmwarepaden in de live Watch-namespace bestaan en leesbaar zijn | Afwezigheid van één kandidaat zegt niets over een ingebedde/dyld-herlocatieerde implementatie |

**Interpretatie van logging:** `sandbox_check=ALLOW` en `bootstrap_look_up kr=0` mogen nooit als 'de wijzerplaat kan worden toegevoegd' worden gepresenteerd. Er is geen library-mutate, geen face-installatie, geen fake systeemidentiteit en geen AppGroup-symlink.

## 3. Vervolgtesten afhankelijk van de eerste vier uitkomsten

| Spoor | Onderzoek / volgende toets | Gate die we willen isoleren | Toelatingsvoorwaarde |
|---|---|---|---|
| **T5: Library XPC-contract** | In originele 23U95 daemon de exacte exported `NSXPCInterface`-selector en intern server-object traceren; caller audit-token en entitlementchecks uit disassembly | Kan een gewone Watch-app überhaupt een **read-only** gestructureerde library-status opvragen? | Pas device-contact overwegen wanneer T1/T2 lookup vrijgeven en methoden aantoonbaar alleen lezen |
| **T6: CLKDevice/PDR-eigenaar** | Matching 23U95 `ClockKit` en NanoRegistry/paired registry offline traceren van `collectionType` en `deviceCategory` naar herkomst/eigenaar; iOS-26.1 `CLKDevice` is slechts vergelijkingsmateriaal | Komt de gate uit MG, Apple-private NanoRegistry of een proces-lokale descriptor? | Geen aanpassing van apparaatidentiteit; eerst bron en authorisatie bewijzen |
| **T7: Native library record path** | Volg originele `NTKDCollectionStore._queue_addFace`, sync reset, JSON deserialisatie, gallery reloading en `faceBundleForBundleIdentifier` volledig (gecontroleerd per SHA + codeflow) | Is een native opgeslagen record onafhankelijk van galerie-enumeratie of wordt het opnieuw gefilterd bij render? | Alleen statisch; geen `resetWithFaces` naar echt apparaat wegens risico op verlies bestaande wijzerplaten |
| **T8: Snapshot/migration exception** | Reconstrueer op 23U95 het eerder openstaande `0x55CE73DC` FaceBundleManager-exceptiepredicaat en exacte callercontext | Is een gelimiteerde interne uitzonderingsroute relevant buiten de Apple snapshots/migratie? | Niet aannemen dat een migratievlag systeem-eligibility overrulet; geen ZIP-tests zonder nieuwe data |
| **T9: App Group Class7** | Vergelijk eerder bestaande `BQRunClass7ControlMatrix` met daadwerkelijke app entitlement, issuerprofiel en `open(O_RDWR)` in **uitsluitend eigen testcontainer** | Verkrijgt dezelfde signer een echt schrijfbare uitbreiding in een **zelf beheerde** App Group? | Alleen met App Group-entitlement die werkelijk in ondertekende app zit; een write in eigen groep bewijst geen write in Apple's systeemgroep |
| **T10: Native Carousel na herstart** | UI-validatie op Watch zelf: systeemgalerij, actieve wijzerplaat, verwijderen/herselecteren, herstart en app sluiten | Uiteindelijk functionaliteit/persistentie | Pas na aantoonbaar toegestane/native toevoeging, nooit voor een alleen-leesdiagnosticum |

## 4. Alternatieve routes: concrete feiten vs speculatie

- **MobileGestalt cache direct via `bad_query` Class13:** echte Watch-resultaten `O_RDWR=EPERM`; kernel 23U95 eist Apple system-group autorisatie. Opnieuw dezelfde flags draaien levert geen nieuwe informatie.
- **Een andere App Group via Class7:** nuttig als brononderzoek, maar `/private/var/mobile/Library/NanoTimeKit` en `FaceSupport` zijn in de onderzochte daemon **geen bekende gewone AppGroup-root**. AppGroup-toegang tot een willekeurig doel maakt de systeemgalerij niet toegankelijk.
- **Preference `ShowHardwareSpecificFaces` zetten:** de originele 23U95-functie short-circuitt bij `NTKInternalBuild=false`. Zonder andere autorisatie is dit geen bypass.
- **Gallerij- of thumbnailcache aanpassen:** een andere representatie op het scherm is niet gelijk aan een legitiem `NTKFace`-object; native lookup en klassebescherming blijven.
- **Een echte systeemface ontvangen via eerstelijns import:** herhaalde `_NTKCanAddWatchFace` en descriptorcontroles; geen bewezen native unlock.
- **Privileged first-party daemon:** heeft aantoonbare store-permissies, maar T1/T2 en T5 moeten uitwijzen of hij überhaupt een geldige niet-Apple client accepteert. Een mach-poort is geen privilege.
- **WatchOS 27 sandboxuitgifte:** de originele Apple sandbox issuerregels verschillen aantoonbaar van 23U95; watchOS 27 PoC's zijn niet automatisch compatibel.

## 5. Stopvoorwaarden en onderzoeksbewijs

- Geen write-, unlink-, symlink- of resetacties in Apple-containers in `Native Face Lab`.
- Leg exacte foutcodes vast, niet slechts 'werkt niet'. `ENOENT`, `EPERM`, sandbox policy `DENY`, geen bootstrapport en een afgewezen library API zijn verschillende uitkomsten.
- Bij ontbrekende signed AppGroup of private entitlements **niet** doen alsof ze door een andere flag verkregen zijn.
- iPhone- en Watch-processen gebruiken niet altijd dezelfde apparaatdescriptor: `CLKDevice` kan via NanoRegistry/PDR toegang opbouwen en de fallback is procesafhankelijk.
- Succes pas wanneer een originele Hermès FaceBundle in Apples eigen systeemgalerij op de Watch verschijnt, zonder een draaiende helper, ook na opnieuw selecteren/herstart.

**Huidige status:** T1–T4 zijn in code geïmplementeerd en worden door GitHub Actions gecompileerd; er zijn nog **geen fysieke Watch-logresultaten** van deze vier tests. Spoor T5–T10 is doelbewust nog niet als risicovolle device-write uitgevoerd.


## 18 november: T5 TCC / Software Update — nieuwe fysieke meetproef

De originele 23U95 firmware en de oorspronkelijke watchOS 26→27 TCC-binaryvergelijking in `Research/2026-11-18-original-tcc-patch-delta.md` wijzen op nieuwe TCC-pad- en containercontroles in 27. Dit is **geen bewezen CVE-entrypoint**. Test daarom eerst uitsluitend **T5**, rechtstreeks op de Watch in het **Native Face Lab**:

- App-proces: `uid/euid/gid/egid`.
- Voor de exacte door launchd gebruikte namen `com.apple.tccd`, `com.apple.mobile.softwareupdated` plus MG/ClockKit-controles: `sandbox_check(mach-lookup)`. Er worden geen XPC-berichten of RPC's verstuurd.
- `lstat` voor de bestaande MobileGestalt-plist: bestandstype, mode, `st_uid`, `st_gid`, grootte; **geen wijziging of write-open**.
- `sandbox_check(file-write-data)` voor diezelfde plist, alleen preflight; geen schrijftest.
- Rapport `protected-writer-service-gate.txt` gaat via WatchConnectivity naar de iPhone, zoals de andere rapporten.

**Beslisboom:** Mach DENY voor TCC/Software Update betekent dat een normale Watch-app niet rechtstreeks met die dienst kan spreken; ALLOW bewijst alleen dat de sandbox deze *naam* niet blokkeert, niet dat het serviceverzoek toegestaan is. `st_uid==geteuid` maakt de POSIX-eigendom plausibel, maar heft de kernel-sandbox niet op. Er bestaat nog **geen** bewijs voor een misbruikbare path-traversal-RPC of native Hermès-ontgrendeling. Zoek pas na relevante toegang naar gedocumenteerde en begrensde autorisatiecontroles; ga niet blind Apple-systeembestanden muteren.


## 18 november: werkelijke Watch6,18 T5 + T2 uitslag (fysiek gemeten)

Bron: rechtstreeks door gebruiker gedeelde Native Face Lab rapporten, Watch6,18 / watchOS `23U95`, 18 november 2026 07:31–07:32 UTC. Hier staan uitsluitend niet-destructieve metingen; geen protected write of Hermès-activatie.

**T5 — effectieve app sandbox versus POSIX:**

| Dienst/controle | Waarde |
|---|---|
| app UID/EUID/GID/EGID | `501/501/501/501` |
| MobileGestalt cache | bestaand regulier bestand, `0644`, `uid=501 gid=501`, `13325` bytes |
| `st_uid == geteuid` | **YES**; POSIX is niet de directe blokkade |
| `sandbox_check(file-write-data, MG)` | **DENY (1)**; kernel-sandbox blijft directe blokkade |
| `mach-lookup com.apple.tccd` | ALLOW (preflight) |
| `mach-lookup com.apple.mobile.softwareupdated` | DENY (1) |
| `mach-lookup com.apple.mobilegestalt.xpc` | ALLOW (preflight) |
| `mach-lookup com.apple.ClockKit.CLKWatchFaceLibrary` | ALLOW (preflight) |

**T2 — echte bootstrap naamresolutie vanaf dezelfde Watch-app:**

| Diensten | `bootstrap_look_up` |
|---|---|
| `com.apple.tccd` | `kr=0`, send right verkregen |
| `com.apple.mobilegestalt.xpc` | `kr=0`, send right verkregen |
| `com.apple.ClockKit.CLKWatchFaceLibrary` | `kr=0`, send right verkregen |
| `com.apple.NanoTimeKit.complication` | `kr=0`, send right verkregen |
| `com.apple.mobile.softwareupdated` | `kr=1100` (**BOOTSTRAP_NOT_PRIVILEGED**) |
| acht native gallery/library/store/replication/Carousel-servicenamen | `kr=1100` (**BOOTSTRAP_NOT_PRIVILEGED**) |

**Belangrijk: `1100 != 1102`.** In de Apple/launchd bootstrap-headers: `BOOTSTRAP_NOT_PRIVILEGED=1100`; `BOOTSTRAP_UNKNOWN_SERVICE=1102`. Dus de negatieve resultaten betekenen *autorisatiefout*, niet simpelweg *dienst ontbreekt*. Zie https://github.com/theos/headers/blob/master/bootstrap.h .

### Nieuwe conclusie en technische prioriteit

1. **TCC:** gebruikersproces kan naam resolven en Mach send right verkrijgen. Een werkelijke XPC-RPC, diens audit-token/entitlementvalidatie en vooral **toegang van de TCC-daemon zelf tot de MobileGestalt-SystemGroup** zijn *niet* bewezen. Eerdere originele `tccd` sandboxprofielanalyse zag schrijfrechten voor TCC-specifieke opslag, niet voor MG. De TCC-watchOS27-binarydelta is bewijs voor gewijzigde padbehandeling, maar **geen aan de CVE gekoppelde exploit**.
2. **MobileGestaltHelper:** ook werkelijk bereikbaar qua Mach port; bestaand onderzoek meldde error 9 bij read/query-paden en heeft geen geverifieerd geautoriseerd writer-protocol ontdekt. Vermijd dezelfde mislukte XPC-aanroepen zonder nieuw bewijs.
3. **Software Update en rechtstreekse NanoTimeKit-brokers:** vanuit deze app *niet* via geteste bootstrapnamen bereikbaar (`1100`); andere alias/service naam niet zonder firmwarebewijs verzinnen.
4. **POSIX:** eigendom `501` is gunstiger dan gedacht, maar maakt geen systeemcontainer schrijfbaar. Rechtstreekse MG-writes blijven `EPERM` onder effectief sandboxbeleid.
5. **Volgende offline onderzoek:** valideer in originele exact passende TCC/MobileGestaltHelper code de concrete client-entitlement- en padrestricties en meet veilig eerst documenteerde read-only operaties. Geen beschermd bestand muteren op basis van `bootstrap_look_up=0` alleen.

Nieuwe Watch UI toont nu ook tekst voor elke Mach bootstrap-returncode; deze wijziging beïnvloedt uitsluitend de logweergave.


## 18 november 2026 — fysieke T6-uitlezing en originele daemon-sandbox (verifieerbaar)

**Fysieke Watch6,18 build 23U95, 08:18:30 UTC (user-provided log):**

```
=== Native Face Boundary Lab · T6: effective Apple daemon policy ===
UNKNOWN: proc_listallpids list failed=1 (Operation not permitted)
```

**T6 testverdict = UNKNOWN**. Het proces `proc_listallpids` is al geblokkeerd voor deze developer-signed Watch-app; daarom is nooit een PID van `tccd`, `softwareupdated` of `MobileGestaltHelper` geïdentificeerd, en **is `sandbox_check(pid, "file-write-data", MG)` nooit aangeroepen tegen die processen**. Dit bewijst dus noch een remote ALLOW noch een remote DENY. Stop met variaties van deze proceslijsttest zonder een nieuwe gerechtvaardigde autorisatie.

**Daarna origineel exact passend sandboxprofiel offline gecontroleerd**: eerder succesvol geëxtraheerd [Watch6,18/23U95 sandbox-artifact #44175646728](https://github.com/mkalter/TESTAPP/actions/runs/44175646728), `profile-com.apple.tccd.sb` (529 regels) plus `profile-baseline.sb` (8078 regels), afkomstig uit de originele Watch6,18 kernelcache. In het **specifieke** `com.apple.tccd`-profiel:
- `file-read*` is expliciet algemeen toegestaan, met een specifieke uitsluitlijst.
- Expliciete `allow file-write*` en `file-write-create` gelden voor `${HOME}/Library/TCC`, CompanionSync-logopslag en `/private/var/mobile/tmp/com.apple.tccd` en `/private/var/tmp/com.apple.tccd`.
- Er is **geen** `/private/var/containers/Shared/SystemGroup` en geen `mobilegestaltcache` in de directe `com.apple.tccd`-profieltekst.
- Het overgeërfde `baseline` bevat een speciale `common-mobilegestalt-rules` **read**/metadata-allow voor de exacte cache, maar niet zo'n expliciete ongeclausuleerde cache-write.
- De `baseline` `file-write-data` SystemGroup-branches bevatten de gebruikelijke `com.apple.sandbox.system-group` en Apple-private `com.apple.security.system-group-containers`/`com.apple.security.system-groups` voorwaarden (naast andere voorwaardelijke opties). Het profielonderzoek is een **statische regelvergelijking**, geen volledige live effectieve sandbox evaluatie met runtime entitlements en eventuele dynamische extensions.

**TCC-route herprioritering**: fysieke `bootstrap_look_up(com.apple.tccd)=0` betekent bereikbaarheid. De in originele TCC disassembly gevonden `registerNewDBAtPath:` leidt naar interne `evalDB:locked:bind:step:` SQL-updates, geen bewezen bestaande-binaire-plist-writer. Noch servicebereikbaarheid, noch een padstring heft de daemon-sandbox op.

**Nieuwe betere kandidaat**: `com.apple.mobilegestalt.xpc` was fysiek op T2 bereikbaar; het originele `MobileGestaltHelper` executable bevat `com.apple.private.security.storage.MobileGestaltCache` en `com.apple.security.system-groups`/doelgroepstrings. Een **werkelijke XML/DER code-signing entitlement decode** is nodig voordat deze strings als cryptografisch gecontroleerde rechten gelden. Zijn bekende XPC-methoden `rebuildCache:` en `setCacheSentinel:` accepteren geen geverifieerde arbitrarily-controlled plist bytes; cache rebuild kan destructief zijn. Geen device-call naar die routes zonder herstelproof.


### 18 november — originele getekende entitlement (niet slechts Mach-O-strings)

[GitHub Actions #44266845679](https://github.com/mkalter/TESTAPP/actions/runs/44266845679) sloot af met **SUCCESS**. De workflow haalde `/usr/libexec/MobileGestaltHelper` uit de originele Watch6,18 / 23U95 Apple IPSW en verifieerde exact SHA256 `0e0c05244a3d35753e948783372f18e615ae2032cf7b750dd7a9cc57cfb3626e`.

Een nieuwe parser las daadwerkelijk `LC_CODE_SIGNATURE` op fileoffset `54736` lengte `21376`, de big-endian Apple `CSMAGIC_EMBEDDED_SIGNATURE` SuperBlob, met:
- `CSSLOT_ENTITLEMENTS=5`, magic `0xfade7171`, XML-Entitlements: **exact één geldig plist-dictionary**;
- `CSSLOT_DER_ENTITLEMENTS=7`, magic `0xfade7172`: DER-entitlementblob **aanwezig** (inhoud niet apart gedecodeerd);
- `com.apple.private.security.storage.MobileGestaltCache: true`;
- `com.apple.security.system-groups:` **[`systemgroup.com.apple.mobilegestaltcache`, `systemgroup.com.apple.mobileactivationd`]**;
- `com.apple.security.system-group-containers` niet in de XML-dict.

De original launchd manifest is onafhankelijk herlezen: `com.apple.mobilegestalt.xpc` -> `/usr/libexec/MobileGestaltHelper`, process identity `mobile` of feature-flag-dependent `_mobilegestalthelper`. Fysiek T2: `bootstrap_look_up` voor deze service **kr=0, port received**.

**Interpretatie**: deze rechten zijn niet louter tekststrings; ze staan daadwerkelijk in de embedded code-signature entitlement-slot van een hashgeverifieerde originele Apple-binary. Dat bevestigt dat deze helper is ingericht voor toegang tot de beschermde MG SystemGroup. Het is nog geen runtime audit van de Apple-handtekeningketen, sandbox tokenconsumptie of effectieve write-open. **Een Mach-port + getekende helper-entitlement bewijst absoluut geen willekeurige client-writer.**

De publieke methodenamen die in dezelfde originele helperbinary worden gevonden zijn `rebuildCache:` en `setCacheSentinel:`. Volgens de gepubliceerde firmwareanalyse kan cache-rebuild de bestaande cache unlinken alvorens regeneratie; sentinel schrijft vaste inhoud naar de sentinelpad. Geen `DeviceBrand`/plisthoudende setter is aangetoond. Daarom **nooit deze muterende helper-API als alleen-leesconnectiviteitstest gebruiken**.

De aanvullende [offline helper-XPC-IMP-map #44267247147](https://github.com/mkalter/TESTAPP/actions/runs/44267247147) onderzoekt de implementaties en autorisatiebranch zonder de dienst aan te roepen.


## 18 november — nieuwe optionele T7 ClockKit-validatie (fysiek nog niet uitgevoerd)

Origineel bevestigd:
- [Originele Watch6,18/23U95 FaceBundle Info.plists #44269491459](https://github.com/mkalter/TESTAPP/actions/runs/44269491459) bewijzen `com.apple.Hermes2025Face` (Hermès 2025) en `com.apple.NTKZeusFaceBundle` (Zeus/Poodle).
- [Originele Watch6,18 dyld ClockKit #44270583446](https://github.com/mkalter/TESTAPP/actions/runs/44270583446) heeft SHA256 `225c004e9a2288799cdad99228076a7b7761befb8686c48407f3f8d0dec59dad`. Die originele Watch-binary bevat de twee bekende ClockKit-validatie-/importselectors; een native NanoTimeKit collectie-mutator werd in deze strings niet gevonden. **Niet hetzelfde als bewezen volledige XPC-protocolaudit.**
- [iPhone + Watch unsigned T7-IPA build #44270806397](https://github.com/mkalter/TESTAPP/actions/runs/44270806397) **SUCCESS**, artifact `unsigned-iphone-watch-ipa` ID `14411579760`.

Nieuwe optionele knop `Native Face Lab → T7 · ClockKit-validatie`:
1. Runtime-aanwezigheid `NSXPCConnection`, `NSXPCInterface` en de in Watch SDK niet-beschikbare maar optioneel dynamische `initWithServiceName:`. Ontbrekend = UNKNOWN.
2. Exposeert uitsluitend read-only `validateFaceType:faceBundleId:completionHandler:` op de door T2 bereikbare ClockKit-Machnaam, géén add/import/mutatieprotocollen.
3. Verstuur één opzettelijk ongeldig controletype (5 seconden timeout) om protocolliveness van native face eligibility te scheiden.
4. Alleen als `NTKFaceBundleStringFromFaceStyle(44)` bestaat, en het echte originele FaceBundle Info.plist op de Watch leesbaar is, vraag Zeus en/of Hermès2025 read-only validatie. Anders SKIP; geen gokwaarden.
5. Retourneer verslag `clockkit-readonly-face-validation.txt` aan iPhone. Een succesvolle validatie bewijst NIET het toevoegen van een originele Hermès-wijzerplaat aan de stock Watch Carousel.

T7 zit bewust NIET in de bestaande knop "Alle 6 lezen en meten". De nieuwe IPA is unsigned en vereist een normale geldige ondertekening/installatie. Nog géén live T7-log, geautoriseerde XPC-bevestiging, systeemface-toevoeging of beschermde MobileGestalt-write bewezen.


## 18 November — T7 transport-v3 exact Apple first-party option

**Physical T7-v1 (08:58 UTC):** read-only invalid control and both native face validations returned no XPC reply, with `NSCocoaErrorDomain/4099` (XPC connection invalidated). The first T7 implementation used `initWithServiceName:` and incorrectly waited three separate timeouts after the first 4099; all original Hermès eligibility results remain **UNKNOWN**, not denied.

**Original Watch6,18 / 23U95 first-party source**: [original dyld Mach-O symbol disassembly #44273680584](https://github.com/mkalter/TESTAPP/actions/runs/44273680584) verified ClockKit SHA `225c004e9a2288799cdad99228076a7b7761befb8686c48407f3f8d0dec59dad` and recovered 8,478 original LC_SYMTAB entries and 26 selected functions. `-[CLKWatchFaceLibraryServer _queue_setupConnectionIfNeeded]` at `0x49c64340` executes `mov w3,#0x1000` at `0x49c64378` and `bl #0x49cccb20` at `0x49c6437c`, consistent with `NSXPCConnectionPrivileged` for a privileged launchd Mach namespace.

**T7-v3 code and build**:
- Uses dynamically checked watchOS runtime `initWithMachServiceName:options:` with **options=0x1000**, matching observed Apple connection option. This is namespace selection, **not privilege or entitlement escalation**.
- The only remote method invoked is `validateFaceType:faceBundleId:completionHandler:`; one intentionally invalid control, followed by the two real signed FaceBundle IDs **only if a real reply is received**.
- Per-request XPC NSError now ends immediately with domain, code and NSDebugDescription; no repeated timeouts upon 4099.
- [Static safety tests #44274693095](https://github.com/mkalter/TESTAPP/actions/runs/44274693095) **SUCCESS**.
- [Combined iPhone+Watch IPA #44274658480](https://github.com/mkalter/TESTAPP/actions/runs/44274658480) **SUCCESS**; artifact `unsigned-iphone-watch-ipa` ID `14414356986`.
- Original first-party XPC stub target symbol crosscheck [run #44274797889](https://github.com/mkalter/TESTAPP/actions/runs/44274797889) requested.

**Next user action**: sign newest **T7-v3** IPA, run `Native Face Lab → T7 · ClockKit-validatie` once on Watch6,18 and return `clockkit-readonly-face-validation.txt`. Do **not** rerun T1–T6 or obsolete T7-v1/v2. A success is a validation answer, not a native stock Hermès face insertion.


## 18 November — real T7-v3 report: ClockKit now responds, both Hermes faces unavailable

Physical Watch6,18/23U95 at **09:27:05 UTC** returned actual
`validateFaceType:faceBundleId:completionHandler:` XPC completions using
the original first-party `initWithMachServiceName:options:` with
`options=0x1000`. No 4099 and no timeout.

| Original submitted test | Genuine XPC reply |
|---|---|
| Deliberately nonexistent face type / nonexistent bundle ID | `CLKWatchFaceLibraryErrorDomain code=4` |
| `type=bundle, bundle=com.apple.NTKZeusFaceBundle` | `CLKWatchFaceLibraryErrorDomain code=4` |
| `type=bundle, bundle=com.apple.Hermes2025Face` | `CLKWatchFaceLibraryErrorDomain code=4` |

Per [Apple ClockKit SDK enum](https://github.com/xybp888/iOS-SDKs/blob/4a48e5409f8ea6ac422c44d91b86fa0f8ae010ff/iPhoneOS26.4.sdk/System/Library/Frameworks/ClockKit.framework/Headers/CLKWatchFaceLibrary.h),
**error code 4 = `CLKWatchFaceLibraryErrorCodeFaceNotAvailable`**,
which differs from permission denied `3` and invalid file `2`.
Thus the XPC **transport and read-only validator method are verified
reachable from this normally signed app**. However, because the deliberately
invalid control receives the *same code 4*, this alone cannot distinguish
model-specific restrictions from an all-false validator context.

**Next discriminator T8 — locally selected POSITIVE CONTROL**: the new
`Native Face Lab → T8 · Positieve Apple-controle` derives an actually
available standard nonbundle style via Apple's local
`NTKFaceDescriptor initWithFaceStyle:` /
`isAvailableForDevice:[CLKDevice currentDevice]`. The style string comes
from the same real `NTKFaceBundleStringFromFaceStyle` runtime. Only then
does it submit `validateFaceType:faceBundleId:` through the already
working XPC transport. If the good control succeeds, T8 compares both
original Hermès IDs. It also logs local Hermès descriptors'
`initWithBundleIdentifier:` and `isAvailableForDevice:` results;
absence of the native availability API returns UNKNOWN and skips remote
tests (no guessed positive control).

**Interpretation of T8**: remote standard success + both Hermès
`FaceNotAvailable` means the validator's availability distinction is
specific to those bundles on this Watch. A standard control rejection
means no safe bundle-specific conclusion from ClockKit alone. Either
case is STILL NOT an Apple native gallery add or persistent unlock.
No imports, protected writes, library reset or device spoofing.


## T8 physical result and corrected build — 18 November 2026 09:42:47 UTC

The user physically ran T8 on **Watch6,18, watchOS 26.6.1 build 23U95**:

```
Local NTKFaceDescriptor=absent CLKDevice=present
currentDevice=present initWithFaceStyle=absent isAvailableForDevice=absent
UNKNOWN: missing local Apple native-face availability API.
Original native style44=bundle
Zeus ID=com.apple.NTKZeusFaceBundle
Hermès2025 ID=com.apple.Hermes2025Face
LOCAL native Zeus availability: NOT AVAILABLE (local descriptor)
LOCAL native Hermès2025 availability: NOT AVAILABLE (local descriptor)
SKIPPED remote differential: no VERIFIED locally available standard control.
```

**Precise interpretation:** the early `NTKFaceDescriptor=absent` was a test
initialization-order issue. Old code called `BQCKKnownAvailableStandardFace`
**before** `BQCKFaceTypeForStyle(44)` had resolved/loaded NanoTimeKit.
Later in this *same* test, **both local Hermès descriptor calls actually
succeeded** and returned false for original bundles on this device.
Thus the "missing native-face API" finding does NOT establish an absent
system framework or an unavailable ordinary face.

**Code corrected on the same experiment branch**:
`BQCKFaceTypeForStyle(44)` is now called **before**
`BQCKKnownAvailableStandardFace`. The next T8 run will check the
same already-loaded Apple descriptor before deciding whether to skip
XPC. Local original Zeus and Hermès2025 availability logging remains.

**Corrected build verified**:
- [iPhone+Watch unsigned IPA #44278019502](https://github.com/mkalter/TESTAPP/actions/runs/44278019502) **SUCCESS**;
  `unsigned-iphone-watch-ipa` artifact `14414879574`, 1,200,737 zip bytes
  and inner IPA ~1,215,575 bytes.
- Original IPA contents checked: both
  `Payload/HermesCompanion.app` and embedded
  `Watch/HermesEnabler2.app` present.
- [Safety/contract CI #44278019492](https://github.com/mkalter/TESTAPP/actions/runs/44278019492) **SUCCESS**.

**Actual NanoTimeKit watchOS gate also disassembled**:
[Original exact 23U95 framework run #44277250878](https://github.com/mkalter/TESTAPP/actions/runs/44277250878)
confirmed style44 bundle lookup uses
`NTKFaceBundleManager faceBundleForBundleIdentifier:onDevice:` and
`isRestrictedForDevice:` on ordinary load, whereas normal nonbundle
styles go via `_NTKFaceStyleIsAvailable`. This explains why a real,
signed original FaceBundle can be installed in `/System/Library`
but not available for the Ultra 1. The special `forMigration:`
branch skips ONE specific restriction call; it has **not** been shown
to authorize installation in the normal native gallery.

**Next physical step:** sign the corrected T8 IPA (not earlier
`44277418407` artifact); run **T8 only** and send
`clockkit-availability-differential.txt`. Do not repeat T1–T7.
No protected write attempted, no native Hermès enabled.


## 18 November 2026 — physical T8 positive control PASS (09:50:24 UTC)

**Physical user-provided report** from `Watch6,18`/watchOS `23U95`,
signed app `com.example.HermesEnabler.Q78LAAPA9S.Q78LAAPA9S.watchkitapp`:

```
Local NTKFaceDescriptor=present CLKDevice=present currentDevice=present
initWithFaceStyle=present isAvailableForDevice=present
POSITIVE CONTROL selected local available style=0 type=utility after 2 descriptor checks
LOCAL native Zeus availability: NOT AVAILABLE (local descriptor)
LOCAL native Hermès2025 availability: NOT AVAILABLE (local descriptor)
Transport=real Apple Mach service options 0x1000
POSITIVE remote control: original standard type=utility style=0 (locally available=YES)
REPLY success (VALIDATION ONLY, NOT FACE ADD)
POSITIVE CONTROL PASS: ClockKit accepted known available standard style.
NATIVE Hermès comparison: style=bundle ID=com.apple.NTKZeusFaceBundle
REPLY NSError domain=CLKWatchFaceLibraryErrorDomain code=4
NATIVE Hermès comparison: style=bundle ID=com.apple.Hermes2025Face
REPLY NSError domain=CLKWatchFaceLibraryErrorDomain code=4
```

**Decision:** The same physically functioning `ClockKit` read-only
validator accepts a *locally proven compatible original Apple utility
style* and rejects **both actual original signed Hermès bundle IDs**
with `CLKWatchFaceLibraryErrorCodeFaceNotAvailable` (4). The
client transport, server method, face style parser, and a general
device context are all operational. Strong evidence of **selective
FaceBundle availability gating on this Ultra 1**. This is not a
generic XPC failure, but it does not by itself prove which individual
`isRestrictedForDevice:` subcondition caused the rejection.

**Next separate T9 (no on-device result yet)**: call the original
in-process, locally resolved
`NTKFaceBundleManager faceBundleForBundleIdentifier:onDevice:forMigration:`
with `NO` then `YES` then `NO` for each of the two original signed
Hermès IDs; log whether the *local returned bundle object* changes and
the genuine face class's `isRestrictedForDevice:` result.
This is **not** Apple's mutating library migration, and **never**
calls `_migrateFacesInStore:`, `_fromSyncResetWithFaces:`,
`setOrderedUUIDs:`, `synchronize`, or any Carousel API.
It may load signed Apple bundle metadata into a cache in this
app process; no persistent library/gallery writing requested.

The original 23U95 NanoTimeKit disassembly proves
`forMigration=YES` skips a specific
`isRestrictedForDevice:` call in *bundle manager lookup*.
Do not interpret a nonnil migration lookup as native Hermès
activation, persistent native library insertion, or rendering.
**T9's real Watch result remains UNKNOWN until actual log received.**


## T9 physically confirmed + T10 targeted read-only classification — 18 Nov 10:06 UTC

**Exact user Watch6,18 / 23U95 T9**:
- Original signed Zeus/Poodle `com.apple.NTKZeusFaceBundle`: normal NO = NIL; migration YES = NIL; normal recheck NO = NIL. **No lookup bypass observed for Zeus**.
- Original signed Hermès2025 `com.apple.Hermes2025Face`: normal NO = NIL; migration YES = **NONNIL** genuine `NTKHermes2025FaceBundle.Hermes2025Face`; face-class `isRestrictedForDevice:YES`; normal recheck NO = NIL. **In-process migration exception is physically proven** but native FaceStore insert, Carousel rendering and persistence remain unproven.

### Why DeviceBrand-only might still fail even with MobileGestalt write authority

Exact original binary `NTKHermes2025FaceBundle` SHA256
`ca8f29bd478483d5bfcd6a30cae9f324a37e2655e0515a27929596df4dc9af49`
was independently reextracted/verified in
[firmware run #44283136629](https://github.com/mkalter/TESTAPP/actions/runs/44283136629).
The real restriction helper at `0x46b8` branches on deviceCategory
whitelist `{2,3,5}` (`tbz w21,#0,0x4770` at `0x4704`, restricted
`mov w0,#1` at `0x4770`) *before* later `collectionType==5` at
`0x4744`. The original same-build CLKDevice loader derived category
from the sizeClass mapping; category 4/6 mark Ultra in the previously
independent [RO23 V13 original code audit](https://github.com/pookjw/HermesEnabler/issues/17).
`DeviceBrand=1` selects `collectionType=5` but does not by itself
change that separate size-class-derived category. **A DeviceBrand-only
write is therefore not a proven Hermès2025 solution.**

### New T10 (optional; not yet physically executed)

`Native Face Lab → T10 · Hermès 2025-apparaatcontrole` reads only
`CLKDevice currentDevice` getters:
`sizeClass`, `deviceCategory`, `deviceBrand`, `collectionType`,
`isUltra`, `supportsFall2025FacesCapability`. It evaluates the
actual on-device value against Hermes2025 category whitelist
`{2,3,5}` and `collectionType==5`. Absent getters return UNKNOWN;
no runtime spoofing, MG cache write, FaceStore or Carousel mutation.

**Build verified**: [iPhone/Watch unsigned IPA #44283783343](https://github.com/mkalter/TESTAPP/actions/runs/44283783343)
SUCCESS, artifact ID `14418416811`, containing full iPhone host and
embedded Watch target. [Safety contract #44283835742](https://github.com/mkalter/TESTAPP/actions/runs/44283835742)
SUCCESS. Normal developer signing required for physical run.

The independent [original 23U95 ClockKit `_loadDeviceInfo` audit #44284560059](https://github.com/mkalter/TESTAPP/actions/runs/44284560059)
tests whether sizeClass/category are driven by a property MobileGestalt
could change, rather than assuming `main-screen-class` changes it.
No native original Hermès face has been persisted.
