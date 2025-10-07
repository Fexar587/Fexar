# Quick Start Guide / Szybki Start

[English](#english) | [Polski](#polski)

---

## English

### Quick Setup (5 minutes)

1. **Setup Android Device/VM:**
   ```bash
   # Connect to your Android device
   adb devices
   
   # For VirtualBox VM
   adb connect 127.0.0.1:5555
   ```

2. **Install Frida Server:**
   ```bash
   cd scripts
   ./setup_frida.sh
   ```

3. **Install Python Dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Install Rise of Kingdoms:**
   ```bash
   # If you have APK file
   ./scripts/install_rok.sh path/to/rok.apk
   
   # Or install from Google Play Store on device
   ```

5. **Run the Bot:**
   ```bash
   python main.py
   ```

### Main Menu Options

```
1. Test Frida Connection     - Verify everything is working
2. Extract libil2cpp.so      - Dump IL2CPP library
3. Extract metadata          - Dump metadata file
4. Extract Both             - Get both files at once (Recommended)
5. Start Memory Reader      - Monitor game memory in real-time
6. Show Extracted Files     - View extracted file info
```

### First Time Usage

**Step 1:** Test connection
```bash
python frida_setup.py
```

**Step 2:** Launch Rise of Kingdoms on your device

**Step 3:** Extract files
```bash
python main.py
# Choose option 4
```

**Step 4:** Files will be in `extracted/` folder
```
extracted/
├── libil2cpp.so
└── global-metadata.dat
```

### What to Do with Extracted Files?

1. **Analyze with Il2CppDumper:**
   ```bash
   Il2CppDumper.exe extracted/libil2cpp.so extracted/global-metadata.dat output/
   ```

2. **Use with ChatGPT 5:**
   - Upload the files
   - Ask about game structures
   - Generate Frida hooks
   - See `CHATGPT_GUIDE.md` for examples

3. **Analyze with Ghidra:**
   - Import libil2cpp.so
   - Use IL2CPP analyzer
   - Find functions and structures

### Troubleshooting

**Problem:** Device not found
```bash
adb devices
adb connect 127.0.0.1:5555  # For VM
```

**Problem:** Frida server not running
```bash
./scripts/start_frida.sh
```

**Problem:** App not found
```bash
# Check if installed
adb shell pm list packages | grep roc

# Launch manually
adb shell am start -n com.lilithgames.roc.gp/.MainActivity
```

### Next Steps

1. ✅ Extract files
2. ✅ Analyze with Il2CppDumper
3. ✅ Use ChatGPT 5 for assistance
4. ✅ Create custom hooks
5. ✅ Build your bot features

---

## Polski

### Szybka Konfiguracja (5 minut)

1. **Skonfiguruj Urządzenie Android/VM:**
   ```bash
   # Połącz z urządzeniem Android
   adb devices
   
   # Dla VirtualBox VM
   adb connect 127.0.0.1:5555
   ```

2. **Zainstaluj Serwer Frida:**
   ```bash
   cd scripts
   ./setup_frida.sh
   ```

3. **Zainstaluj Zależności Python:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Zainstaluj Rise of Kingdoms:**
   ```bash
   # Jeśli masz plik APK
   ./scripts/install_rok.sh sciezka/do/rok.apk
   
   # Lub zainstaluj z Google Play Store na urządzeniu
   ```

5. **Uruchom Bota:**
   ```bash
   python main.py
   ```

### Opcje Menu Głównego

```
1. Test Połączenia Frida    - Sprawdź czy wszystko działa
2. Wydobądź libil2cpp.so    - Zrzuć bibliotekę IL2CPP
3. Wydobądź metadata        - Zrzuć plik metadanych
4. Wydobądź Oba            - Pobierz oba pliki naraz (Zalecane)
5. Uruchom Czytnik Pamięci - Monitoruj pamięć gry w czasie rzeczywistym
6. Pokaż Wydobyte Pliki    - Zobacz info o wydobytych plikach
```

### Pierwsze Użycie

**Krok 1:** Przetestuj połączenie
```bash
python frida_setup.py
```

**Krok 2:** Uruchom Rise of Kingdoms na urządzeniu

**Krok 3:** Wydobądź pliki
```bash
python main.py
# Wybierz opcję 4
```

**Krok 4:** Pliki będą w folderze `extracted/`
```
extracted/
├── libil2cpp.so
└── global-metadata.dat
```

### Co Zrobić z Wydobytymi Plikami?

1. **Analizuj z Il2CppDumper:**
   ```bash
   Il2CppDumper.exe extracted/libil2cpp.so extracted/global-metadata.dat output/
   ```

2. **Użyj z ChatGPT 5:**
   - Wgraj pliki
   - Pytaj o struktury gry
   - Generuj hooki Frida
   - Zobacz `CHATGPT_GUIDE.md` dla przykładów

3. **Analizuj z Ghidra:**
   - Importuj libil2cpp.so
   - Użyj analizatora IL2CPP
   - Znajdź funkcje i struktury

### Rozwiązywanie Problemów

**Problem:** Nie znaleziono urządzenia
```bash
adb devices
adb connect 127.0.0.1:5555  # Dla VM
```

**Problem:** Serwer Frida nie działa
```bash
./scripts/start_frida.sh
```

**Problem:** Nie znaleziono aplikacji
```bash
# Sprawdź czy zainstalowana
adb shell pm list packages | grep roc

# Uruchom ręcznie
adb shell am start -n com.lilithgames.roc.gp/.MainActivity
```

### Następne Kroki

1. ✅ Wydobądź pliki
2. ✅ Analizuj z Il2CppDumper
3. ✅ Użyj ChatGPT 5 do pomocy
4. ✅ Twórz własne hooki
5. ✅ Buduj funkcje bota

---

## Common Commands / Często Używane Komendy

### Start Everything / Uruchom Wszystko
```bash
# 1. Start Frida Server
./scripts/start_frida.sh

# 2. Run Bot
python main.py
```

### Quick Test / Szybki Test
```bash
# Test connection
python frida_setup.py

# List processes
frida-ps -U

# Check if game is running
frida-ps -U | grep roc
```

### Extract Files / Wydobądź Pliki
```bash
# Method 1: Menu
python main.py
# Choose option 4

# Method 2: Direct
python extract_il2cpp.py
python extract_metadata.py
```

### View Logs / Zobacz Logi
```bash
# ADB logs
adb logcat | grep roc

# Frida processes
adb shell ps | grep frida
```

---

## Tips / Wskazówki

### English
- Always start Frida server before running the bot
- Make sure Rise of Kingdoms is running when extracting
- Extracted files are in `extracted/` folder
- Use ChatGPT 5 for help with analysis
- Check `README.md` for full documentation

### Polski
- Zawsze uruchom serwer Frida przed botem
- Upewnij się, że Rise of Kingdoms działa podczas ekstrakcji
- Wydobyte pliki są w folderze `extracted/`
- Użyj ChatGPT 5 do pomocy z analizą
- Sprawdź `README.md` dla pełnej dokumentacji

---

## Support / Wsparcie

- 📖 Full docs: `README.md`
- 🔧 Setup guide: `SETUP_GUIDE.md`
- 🤖 ChatGPT help: `CHATGPT_GUIDE.md`
- 🐛 Issues: GitHub Issues
- 💬 Questions: ChatGPT 5

**Version:** 1.0.0  
**Frida:** 17.3.2  
**Target:** Rise of Kingdoms
