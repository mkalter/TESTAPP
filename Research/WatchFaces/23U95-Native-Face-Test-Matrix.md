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
| negen native gallery/library/store/replication/Carousel-servicenamen | `kr=1100` (**BOOTSTRAP_NOT_PRIVILEGED**) |

**Belangrijk: `1100 != 1102`.** In de Apple/launchd bootstrap-headers: `BOOTSTRAP_NOT_PRIVILEGED=1100`; `BOOTSTRAP_UNKNOWN_SERVICE=1102`. Dus de negatieve resultaten betekenen *autorisatiefout*, niet simpelweg *dienst ontbreekt*. Zie https://github.com/theos/headers/blob/master/bootstrap.h .

### Nieuwe conclusie en technische prioriteit

1. **TCC:** gebruikersproces kan naam resolven en Mach send right verkrijgen. Een werkelijke XPC-RPC, diens audit-token/entitlementvalidatie en vooral **toegang van de TCC-daemon zelf tot de MobileGestalt-SystemGroup** zijn *niet* bewezen. Eerdere originele `tccd` sandboxprofielanalyse zag schrijfrechten voor TCC-specifieke opslag, niet voor MG. De TCC-watchOS27-binarydelta is bewijs voor gewijzigde padbehandeling, maar **geen aan de CVE gekoppelde exploit**.
2. **MobileGestaltHelper:** ook werkelijk bereikbaar qua Mach port; bestaand onderzoek meldde error 9 bij read/query-paden en heeft geen geverifieerd geautoriseerd writer-protocol ontdekt. Vermijd dezelfde mislukte XPC-aanroepen zonder nieuw bewijs.
3. **Software Update en rechtstreekse NanoTimeKit-brokers:** vanuit deze app *niet* via geteste bootstrapnamen bereikbaar (`1100`); andere alias/service naam niet zonder firmwarebewijs verzinnen.
4. **POSIX:** eigendom `501` is gunstiger dan gedacht, maar maakt geen systeemcontainer schrijfbaar. Rechtstreekse MG-writes blijven `EPERM` onder effectief sandboxbeleid.
5. **Volgende offline onderzoek:** valideer in originele exact passende TCC/MobileGestaltHelper code de concrete client-entitlement- en padrestricties en meet veilig eerst documenteerde read-only operaties. Geen beschermd bestand muteren op basis van `bootstrap_look_up=0` alleen.

Nieuwe Watch UI toont nu ook tekst voor elke Mach bootstrap-returncode; deze wijziging beïnvloedt uitsluitend de logweergave.
