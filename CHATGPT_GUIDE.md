# Przewodnik Użycia ChatGPT 5 z Rise of Kingdoms Bot

Ten dokument pokazuje jak używać ChatGPT 5 do analizy wydobytych plików i tworzenia zaawansowanych funkcji bota.

## Przygotowanie Plików

Po wydobyciu plików z gry:
```bash
cd extracted/
ls -lh
# libil2cpp.so
# global-metadata.dat
```

## Analiza z ChatGPT 5

### 1. Podstawowa Analiza Struktur

**Pytanie do ChatGPT:**
```
Mam dwa pliki z gry Rise of Kingdoms:
- libil2cpp.so (biblioteka IL2CPP)
- global-metadata.dat (metadata IL2CPP)

Chcę znaleźć struktury danych dla:
1. Zasoby gracza (złoto, jedzenie, drewno, kamień)
2. Pozycja armii na mapie
3. Statystyki dowódców

Jak mogę to zrobić?
```

### 2. Analiza Funkcji IL2CPP

**Pytanie do ChatGPT:**
```
Na podstawie dumpów IL2CPP z Rise of Kingdoms, szukam funkcji odpowiedzialnych za:
1. Aktualizację zasobów
2. Ruch armii
3. Budowanie budynków

Jakie typowe nazwy funkcji IL2CPP powinienem szukać?
```

**Przykładowa odpowiedź ChatGPT:**
```
Szukaj funkcji takich jak:
- PlayerResources_UpdateGold
- Army_Move
- Building_StartConstruction
- ResourceManager_AddResource

Użyj Il2CppDumper lub Ghidra do analizy.
```

### 3. Generowanie Skryptów Frida

**Pytanie do ChatGPT:**
```
Wygeneruj skrypt Frida, który hookuje funkcję IL2CPP o nazwie "PlayerResources_GetGold" 
i wypisuje jej wyniki. Funkcja znajduje się w module libil2cpp.so.
```

**Przykładowa odpowiedź ChatGPT:**
```javascript
Java.perform(function() {
    var il2cpp_base = Module.findBaseAddress("libil2cpp.so");
    
    // Znajdź funkcję przez export
    var getGold = Module.findExportByName("libil2cpp.so", "PlayerResources_GetGold");
    
    if (getGold) {
        Interceptor.attach(getGold, {
            onEnter: function(args) {
                console.log("[*] GetGold called");
                console.log("    this: " + args[0]);
            },
            onLeave: function(retval) {
                console.log("[*] GetGold returned: " + retval.toInt32());
            }
        });
    }
});
```

### 4. Dekodowanie Offsetów Pamięci

**Pytanie do ChatGPT:**
```
Z Il2CppDumper otrzymałem następujące offsety dla klasy PlayerData:
- Gold: 0x18
- Food: 0x1C
- Wood: 0x20
- Stone: 0x24

Jak utworzyć skrypt Frida do odczytu tych wartości?
```

**Przykładowa odpowiedź ChatGPT:**
```javascript
function readPlayerData(baseAddress) {
    var gold = Memory.readU32(baseAddress.add(0x18));
    var food = Memory.readU32(baseAddress.add(0x1C));
    var wood = Memory.readU32(baseAddress.add(0x20));
    var stone = Memory.readU32(baseAddress.add(0x24));
    
    console.log("=== Player Resources ===");
    console.log("Gold: " + gold);
    console.log("Food: " + food);
    console.log("Wood: " + wood);
    console.log("Stone: " + stone);
}
```

## Przykładowe Scenariusze

### Scenariusz 1: Znajdowanie Instancji Gracza

**Prompt dla ChatGPT:**
```
Jak znaleźć instancję obiektu gracza (PlayerInstance) w pamięci IL2CPP?
Zwykle są to singletony dostępne przez statyczne metody.
```

**Skrypt wygenerowany przez ChatGPT:**
```javascript
// Znajdź metodę getInstance()
var getInstance = Module.findExportByName("libil2cpp.so", 
    "PlayerManager_getInstance");

if (getInstance) {
    var getInstanceFunc = new NativeFunction(getInstance, 'pointer', []);
    var playerInstance = getInstanceFunc();
    
    console.log("Player Instance at: " + playerInstance);
    
    // Czytaj dane
    readPlayerData(playerInstance);
}
```

### Scenariusz 2: Monitoring Zmian Zasobów

**Prompt dla ChatGPT:**
```
Stwórz skrypt Frida, który monitoruje wszystkie zmiany zasobów gracza
i wypisuje stacktrace, aby zobaczyć skąd pochodzą zmiany.
```

**Skrypt wygenerowany przez ChatGPT:**
```javascript
var addResource = Module.findExportByName("libil2cpp.so", 
    "ResourceManager_AddResource");

Interceptor.attach(addResource, {
    onEnter: function(args) {
        var resourceType = args[0].toInt32();
        var amount = args[1].toInt32();
        
        console.log("\n[*] AddResource called:");
        console.log("    Type: " + resourceType);
        console.log("    Amount: " + amount);
        console.log("\nStacktrace:");
        console.log(Thread.backtrace(this.context, Backtracer.ACCURATE)
            .map(DebugSymbol.fromAddress).join('\n'));
    }
});
```

### Scenariusz 3: Zrozumienie Struktur Danych

**Prompt dla ChatGPT:**
```
Mam dump pamięci obiektu Commander:
00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
47 65 6E 67 68 69 73 00 05 00 00 00 32 00 00 00

Pomóż mi zrozumieć strukturę tego obiektu.
```

**Analiza ChatGPT:**
```
Wygląda na:
- Offset 0x00-0x07: Nazwa dowódcy (string) = "Genghis"
- Offset 0x08: Poziom = 5
- Offset 0x0C: Doświadczenie = 50 (0x32)

Struktura:
struct Commander {
    char name[8];    // +0x00
    uint32_t level;  // +0x08
    uint32_t exp;    // +0x0C
};
```

## Zaawansowane Użycie

### Automatyczne Generowanie Hooków

**Prompt:**
```
Na podstawie dump.cs z Il2CppDumper, wygeneruj kompleksowy 
skrypt Frida do monitorowania wszystkich metod klasy BattleManager.
```

### Reverse Engineering Algorytmów

**Prompt:**
```
Znalazłem funkcję CalculateDamage w IL2CPP. Oto jej pseudo-kod z Ghidra:
[wklej pseudo-kod]

Wyjaśnij jak działa algorytm obliczania obrażeń.
```

### Tworzenie Bota

**Prompt:**
```
Chcę stworzyć bota, który automatycznie:
1. Zbiera zasoby z farm
2. Trenouje jednostki
3. Wysyła armie na misje

Na podstawie wydobytych plików IL2CPP, jakie funkcje powinienem hookować?
```

## Przykładowy Workflow

### Kompletny Proces Analizy

1. **Wydobądź pliki:**
```bash
python main.py
# Wybierz opcję 4
```

2. **Dump IL2CPP z Il2CppDumper:**
```bash
Il2CppDumper.exe extracted/libil2cpp.so extracted/global-metadata.dat output/
```

3. **Zapytaj ChatGPT:**
```
Przeanalizuj dump.cs i znajdź wszystkie klasy związane z zarządzaniem zasobami.
[załącz fragment dump.cs]
```

4. **Stwórz custom hook:**
Użyj kodu wygenerowanego przez ChatGPT w `memory_reader.py`

5. **Testuj:**
```bash
python memory_reader.py
```

## Szablony Pytań dla ChatGPT

### Dla Początkujących

```
1. "Jak działa IL2CPP i czym różni się od standardowego Mono?"
2. "Wyjaśnij strukturę pliku global-metadata.dat"
3. "Jakie narzędzia mogę użyć do analizy libil2cpp.so?"
4. "Jak znaleźć funkcje związane z [funkcjonalność] w dumpie IL2CPP?"
```

### Dla Zaawansowanych

```
1. "Wygeneruj skrypt Frida do patchowania funkcji [nazwa] w runtime"
2. "Jak mogę znaleźć wszystkie referencje do klasy [nazwa] w pamięci?"
3. "Stwórz analizator pamięci dla struktur typu [typ]"
4. "Pomóż zoptymalizować mój skrypt Frida [wklej kod]"
```

## Najlepsze Praktyki

1. **Bądź Konkretny**
   - Podawaj konkretne nazwy funkcji/klas
   - Załączaj fragmenty kodu/dumpów
   - Opisz dokładnie co chcesz osiągnąć

2. **Dziel na Małe Zadania**
   - Zamiast "stwórz kompletnego bota"
   - Pytaj o pojedyncze funkcje: "jak hookować funkcję X?"

3. **Iteruj**
   - Testuj odpowiedzi ChatGPT
   - Wracaj z błędami i logami
   - Proś o poprawki i ulepszenia

4. **Dokumentuj**
   - Zapisuj działające skrypty
   - Notuj offsety i struktury
   - Twórz własną bazę wiedzy

## Przykładowe Sesje

### Sesja 1: Znajdowanie Zasobów
```
User: Mam libil2cpp.so i metadata z Rise of Kingdoms. 
      Jak znaleźć gdzie w pamięci są przechowywane zasoby gracza?

ChatGPT: [szczegółowa odpowiedź z krokami]

User: Użyłem Il2CppDumper i znalazłem klasę ResourceManager. 
      Co dalej?

ChatGPT: [generuje skrypt Frida]

User: Skrypt nie działa, dostaję error [error message]

ChatGPT: [debuguje i poprawia]
```

### Sesja 2: Tworzenie Hooka
```
User: Chcę zhookować funkcję Battle_CalculateDamage. 
      Jak to zrobić?

ChatGPT: [generuje kod]

User: Działa! Czy mogę też zmodyfikować wartość zwracaną?

ChatGPT: [pokazuje jak modyfikować retval]

User: Doskonale! Jak zapisać te dane do pliku?

ChatGPT: [dodaje logging do pliku]
```

## Dodatkowe Zasoby

### Przydatne Prompty

**Analiza Kodu:**
```
"Wyjaśnij co robi ta funkcja IL2CPP: [kod]"
```

**Debugging:**
```
"Mój skrypt Frida daje błąd: [error]. Pomóż naprawić."
```

**Optymalizacja:**
```
"Jak mogę zoptymalizować ten skrypt: [kod]"
```

### Linki do Nauki

ChatGPT może polecić:
- Dokumentację Frida
- Tutoriale IL2CPP
- Przykładowe projekty
- Narzędzia analizy

## Podsumowanie

ChatGPT 5 to potężne narzędzie do:
- ✅ Analizy struktur IL2CPP
- ✅ Generowania skryptów Frida
- ✅ Debugowania problemów
- ✅ Nauki reverse engineering
- ✅ Automatyzacji zadań

Używaj go jako asystenta na każdym etapie rozwoju bota!

---

**Pamiętaj:** ChatGPT to narzędzie pomocnicze. Zawsze testuj wygenerowany kod i rozumiej co robi!
