# 18 November 2026 — Routebesluit: MobileGestalt versus native Hermès 2025 FaceStore

**Toestel** Apple Watch Ultra 1 `Watch6,18`; **build** watchOS 26.6.1 `23U95`.
**Doel** een *originele*, persistent werkende native Hermès wijzerplaat binnen het Apple Watch systeem, niet een standalone render of nagemaakte galerij.

## Wat op het echte toestel is aangetoond

- T7: oorspronkelijke ClockKit Mach-server is bereikbaar met Apple's eigen `initWithMachServiceName:options:` `0x1000`; beide originele Hermès FaceBundles kregen `FaceNotAvailable=4`.
- T8: **positieve controle**: echte standaardstijl `utility`, style0, was lokaal beschikbaar én kreeg `REPLY success` van dezelfde server. Zeus en Hermès2025 waren lokaal niet beschikbaar en kregen beide `FaceNotAvailable=4`. Daardoor is dit **selectieve face-eligibility**, geen transportfout.
- T9: `Hermes2025` normale `forMigration:NO` lookup **NIL**, migratie `forMigration:YES` **NONNIL** originele `Hermes2025Face`, hercontrole normaal opnieuw **NIL**; face class `isRestrictedForDevice:YES` blijft. Zeus/Poodle blijft NIL voor beide routes. Deze migratielookup maakt **geen face library entry**.

## Originele Hermès2025-code — categorie gaat vóór merkcollectie

De nieuwe [exacte Apple Watch6,18/23U95 FaceBundle audit](https://github.com/mkalter/TESTAPP/actions/runs/44283136629)
haalde de originele `NTKHermes2025FaceBundle` uit Apple's IPSW,
geverifieerde SHA256:
`ca8f29bd478483d5bfcd6a30cae9f324a37e2655e0515a27929596df4dc9af49`.

In `+[Hermes2025Face isRestrictedForDevice:]` (0x3b2c) roept Apple
de helper op 0x46b8 aan. De relevante letterlijke ARM64-instructies zijn:

```asm
0x46ec bl    0xc8320           ; deviceCategory (independently resolved in V13)
0x46f4 bl    0x6e67c           ; set membership
0x4704 tbz   w21,#0,0x4770   ; if category not allowed -> return restricted
...
0x4740 bl    0xc8080           ; collectionType (independently resolved in V13)
0x4744 cmp   w0,#5
0x4748 b.ne  0x475c
...
0x4770 mov   w0,#1            ; restricted
```

De in de originele Swift-set geïdentificeerde categorieën zijn **{2,3,5}**,
via de eerdere onafhankelijke V13 binary analyse
([upstream Issue 17 / V13](https://github.com/pookjw/HermesEnabler/issues/17)).
De originele ClockKit `CLKDevice.isUltra` wordt afgeleid uit deviceCategory
**4 of 6**; die vallen buiten de Hermès2025 whitelist.
Het is een voorwaardelijke afleiding uit dezelfde firmware: de exacte
huidige Ultra-categorie wordt afzonderlijk via T10 gemeten.

Dezelfde eerdere eerste-partij ClockKit-analyse:
- `DeviceBrand=1` selecteert `collectionType=5`, die een **later** criterium raakt.
- De `deviceCategory` wordt uit `sizeClass` berekend, een apart veld.
- **Niet bewezen** dat alleen `DeviceBrand=1` genoeg is. Zelfs succesvolle
  MobileGestalt cachewijziging kan Hermès2025 nog op categorie laten afvallen.
- **Niet bewezen** of `main-screen-class` in MobileGestalt op deze build
  de effectieve `sizeClass`/deviceCategory of NanoRegistry cache beïnvloedt.
  Een hypothetische wijziging van meerdere MG keys is dus ook geen aangetoonde oplossing.

## MobileGestalt — schrijfrechten zijn de grootste directe blokkade

Fysiek dezelfde Ultra 23U95: bestaande protected
`systemgroup.com.apple.mobilegestaltcache/.../com.apple.MobileGestalt.plist`
kan worden gelezen, maar `O_WRONLY/O_RDWR` en `file-write-data` blijven
**EPERM**. Class7/AppGroup/part-symlink en Class13/SystemGroup tokens,
NSFileCoordinator, InstallCoordination, IOKit provider en de aanwezige
`MobileGestaltHelper` XPC hebben geen gecontroleerde write proof opgeleverd.

De originele `MobileGestaltHelper` heeft wel daadwerkelijk ondertekende
SystemGroup/private-cache-entitlements, maar zijn geverifieerde XPC interface
bevat geen arbitrary plist setter. `rebuildCache:` kan de bestaande cache
verwijderen en mag niet als test worden gebruikt.

Onafhankelijke fysieke gebruikers op watchOS26.6.1 rapporteren dezelfde
read-only/token-without-writable-file grens:
[HermesEnabler issue #90](https://github.com/pookjw/HermesEnabler/issues/90).
Geen reproduceerbare gewone-app-write route voor exact 23U95 vastgesteld.

## Native FaceStore migratie — andere blokkade

De originele NanoTimeKit `forMigration:YES` bundellookup slaat één
`isRestrictedForDevice:` controle over en T9 heeft dat *lokaal* voor
Hermès2025 aangetoond. De originele JSON constructor gebruikt de parameter
daadwerkelijk ([23U95 JSON migration audit](https://github.com/mkalter/TESTAPP/actions/runs/44280447358)).
Maar een derde-partij app kan hiermee nog geen records geautoriseerd in
`nanotimekitd` laten opslaan, laat staan normale galerie-gating of
`_removeUnavailableFacesFromStore:` omzeilen. Native persistentierechten
zijn niet aanwezig of aangetoond.

## Beslisvolgorde en wat we NIET opnieuw testen

1. **Alleen-lezen T10** `hermes2025-live-identity-gates.txt` vraagt
   echte `CLKDevice` getters (sizeClass, deviceCategory, deviceBrand,
   collectionType, isUltra, supportsFall2025FacesCapability). Dit kan
   bepalen of de categoriecontrole al afvalt, zonder MG-aanpassing.
2. Verifieer uit dezelfde originele ClockKit-code waar de sizeClass vandaan
   komt (NanoRegistry vs MobileGestalt `main-screen-class`) vóór we de
   MG-route als een *complete* oplossing beoordelen.
3. Voor MG alleen verder wanneer er een **daadwerkelijk nieuw,
   bewijsbaar en herstelbaar** mechanisme voor geautoriseerde cachewijziging
   bestaat; geen iteratie van bestaande EPERM-routes.
4. Voor FaceStore alleen verder bij vastgesteld geautoriseerd
   Apple-migratieprotocol dat persistente native-library-entry ondersteunt;
   geen speculatieve `_fromSyncResetWithFaces:` mutatie, library reset of
   dummy `.watchface` als bewijs.

**Technisch oordeel:** MobileGestalt is qua gewenste eindtoestand de
kortere weg indien álle noodzakelijke device eigenschappen daarmee
correct kunnen worden beïnvloed, maar de *eerstvolgende blokkade is
zwaarder*: een beschermd systeembestand waarvoor deze app geen write-authority
heeft. Migratie kan nu één Hermès2025 bundle-object lezen, maar lost
normal device eligibility, systeemgalerij en persistentie niet op.
**Geen werkende oorspronkelijke native Hermès activatie bewezen.**
