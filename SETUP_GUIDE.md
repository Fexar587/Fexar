# Szczegółowy Przewodnik Konfiguracji - Rise of Kingdoms Bot

Ten przewodnik pomoże Ci skonfigurować VirtualBox z Androidem oraz Frida 17.3.2 do pracy z botem czytającym pamięć RAM Rise of Kingdoms.

## Wymagania Wstępne

- Komputer z systemem Windows/Linux/MacOS
- VirtualBox 7.0 lub nowszy
- Minimum 8GB RAM (zalecane 16GB)
- 20GB wolnego miejsca na dysku
- Połączenie z internetem

## Krok 1: Instalacja VirtualBox

1. Pobierz VirtualBox:
   ```
   https://www.virtualbox.org/wiki/Downloads
   ```

2. Zainstaluj VirtualBox wraz z Extension Pack

3. Zrestartuj komputer jeśli wymagane

## Krok 2: Konfiguracja Android w VirtualBox

### Opcja A: Android-x86 (Zalecana)

1. Pobierz Android-x86 ISO:
   ```
   https://www.android-x86.org/download
   Zalecana wersja: Android 9.0 (Pie) lub nowsza
   ```

2. Utwórz nową maszynę wirtualną w VirtualBox:
   - Nazwa: Android-RoK
   - Typ: Linux
   - Wersja: Other Linux (64-bit)
   - RAM: 4096 MB (4GB) minimum
   - Dysk: 20GB VDI dynamiczny

3. Konfiguracja VM:
   - System → Procesor: 2-4 rdzenie
   - Wyświetlacz → Pamięć wideo: 128MB
   - Wyświetlacz → Włącz akcelerację 3D
   - Sieć → Adapter 1: NAT
   - USB → Włącz kontroler USB 2.0 lub 3.0

4. Uruchom VM i zainstaluj Android:
   - Wybierz "Installation"
   - Utwórz partycję (cfdisk)
   - Zainstaluj GRUB
   - Zrestartuj

5. Po instalacji:
   - Przejdź przez proces konfiguracji Android
   - Włącz "Opcje deweloperskie" (Settings → About → kliknij 7x "Build number")
   - Włącz "USB Debugging" w opcjach deweloperskich

### Opcja B: Genymotion

1. Pobierz Genymotion:
   ```
   https://www.genymotion.com/download/
   ```

2. Zainstaluj i utwórz wirtualne urządzenie:
   - Google Pixel 3
   - Android 9.0 lub nowszy
   - RAM: 4GB
   - Root access: Enabled

## Krok 3: Root na Android

### Dla Android-x86:
Android-x86 ma domyślnie dostęp root przez adb.

### Dla innych obrazów:
1. Pobierz Magisk:
   ```
   https://github.com/topjohnwu/Magisk/releases
   ```

2. Zainstaluj Magisk na VM

3. Zweryfikuj root:
   ```bash
   adb shell su
   ```

## Krok 4: Instalacja ADB na Komputerze

### Windows:
```bash
# Pobierz Android Platform Tools
https://developer.android.com/studio/releases/platform-tools

# Dodaj do PATH lub użyj z katalogu
cd platform-tools
adb devices
```

### Linux/Mac:
```bash
# Ubuntu/Debian
sudo apt-get install adb

# MacOS
brew install android-platform-tools

# Sprawdź instalację
adb version
```

## Krok 5: Połączenie ADB z VirtualBox

1. Skonfiguruj port forwarding w VirtualBox:
   - VM Settings → Network → Advanced → Port Forwarding
   - Dodaj regułę:
     - Name: ADB
     - Protocol: TCP
     - Host Port: 5555
     - Guest Port: 5555

2. W Android VM uruchom:
   ```bash
   adb tcpip 5555
   ```

3. Na komputerze hosta:
   ```bash
   adb connect 127.0.0.1:5555
   adb devices
   ```

   Powinieneś zobaczyć:
   ```
   127.0.0.1:5555    device
   ```

## Krok 6: Instalacja Rise of Kingdoms

### Metoda 1: Google Play Store (jeśli dostępny)
1. Zaloguj się do Google Play
2. Wyszukaj "Rise of Kingdoms"
3. Zainstaluj grę

### Metoda 2: APK (Zalecana dla VM)
1. Pobierz APK Rise of Kingdoms:
   ```
   https://apkpure.com/rise-of-kingdoms/com.lilithgames.roc.gp
   ```

2. Zainstaluj przez ADB:
   ```bash
   adb install RiseOfKingdoms.apk
   ```

3. Zweryfikuj instalację:
   ```bash
   adb shell pm list packages | grep lilithgames
   ```

## Krok 7: Instalacja Frida Server 17.3.2

1. Sprawdź architekturę Android:
   ```bash
   adb shell getprop ro.product.cpu.abi
   ```

2. Pobierz odpowiednią wersję Frida Server:
   
   **Dla x86_64 (Android-x86):**
   ```bash
   wget https://github.com/frida/frida/releases/download/17.3.2/frida-server-17.3.2-android-x86_64.xz
   ```
   
   **Dla arm64 (niektóre VM):**
   ```bash
   wget https://github.com/frida/frida/releases/download/17.3.2/frida-server-17.3.2-android-arm64.xz
   ```

3. Rozpakuj:
   ```bash
   unxz frida-server-17.3.2-android-*.xz
   ```

4. Prześlij na urządzenie:
   ```bash
   adb push frida-server-17.3.2-android-* /data/local/tmp/frida-server
   ```

5. Ustaw uprawnienia:
   ```bash
   adb shell "chmod 755 /data/local/tmp/frida-server"
   ```

6. Uruchom Frida Server:
   ```bash
   adb shell "su -c /data/local/tmp/frida-server &"
   ```

7. Zweryfikuj, że działa:
   ```bash
   adb shell "ps | grep frida"
   ```

## Krok 8: Instalacja Python i Zależności

1. Zainstaluj Python 3.8+:
   ```bash
   python --version
   ```

2. Zainstaluj pip jeśli nie ma:
   ```bash
   # Windows
   python -m pip install --upgrade pip
   
   # Linux/Mac
   sudo apt-get install python3-pip
   ```

3. Sklonuj repozytorium Fexar:
   ```bash
   git clone https://github.com/Fexar587/Fexar.git
   cd Fexar
   ```

4. Zainstaluj wymagane pakiety:
   ```bash
   pip install -r requirements.txt
   ```

5. Zweryfikuj instalację Frida:
   ```bash
   frida --version
   # Powinno pokazać: 17.3.2
   ```

## Krok 9: Test Konfiguracji

1. Sprawdź połączenie Frida:
   ```bash
   frida-ps -U
   ```
   
   Powinieneś zobaczyć listę procesów Android.

2. Uruchom Rise of Kingdoms na VM

3. Sprawdź czy gra jest widoczna:
   ```bash
   frida-ps -U | grep roc
   ```

4. Uruchom test konfiguracji bota:
   ```bash
   python frida_setup.py
   ```

   Jeśli wszystko działa poprawnie, zobaczysz:
   ```
   [+] Connected via USB
   [+] Device: Android Device
   [+] Frida server is running
   [+] All checks passed!
   ```

## Krok 10: Uruchomienie Bota

1. Uruchom główne menu:
   ```bash
   python main.py
   ```

2. Wybierz opcję 1, aby przetestować połączenie

3. Jeśli test się powiedzie, wybierz opcję 4, aby wydobyć oba pliki:
   - libil2cpp.so
   - global-metadata.dat

4. Pliki zostaną zapisane w katalogu `extracted/`

## Rozwiązywanie Problemów

### Problem: ADB nie widzi urządzenia
**Rozwiązanie:**
```bash
# Zrestartuj ADB
adb kill-server
adb start-server
adb connect 127.0.0.1:5555
```

### Problem: Frida Server się nie uruchamia
**Rozwiązanie:**
```bash
# Sprawdź SELinux
adb shell getenforce
adb shell "su -c setenforce 0"

# Zrestartuj Frida
adb shell "su -c killall frida-server"
adb shell "su -c /data/local/tmp/frida-server &"
```

### Problem: Brak dostępu root
**Rozwiązanie:**
- Upewnij się, że VM ma dostęp root
- Dla Android-x86, root jest domyślnie dostępny
- Sprawdź: `adb shell su -c id`

### Problem: Rise of Kingdoms się crashuje
**Rozwiązanie:**
```bash
# Zwiększ RAM VM do 6-8GB
# Włącz akcelerację sprzętową w VirtualBox
# Sprawdź logi:
adb logcat | grep roc
```

### Problem: Frida nie może się podłączyć do aplikacji
**Rozwiązanie:**
```bash
# Sprawdź czy aplikacja jest uruchomiona
adb shell "ps | grep roc"

# Uruchom aplikację ręcznie
adb shell "am start -n com.lilithgames.roc.gp/.MainActivity"

# Spróbuj ponownie
```

## Użycie z ChatGPT 5

Po wydobyciu plików możesz:

1. Wgraj `libil2cpp.so` i `global-metadata.dat` do ChatGPT 5

2. Zapytaj o:
   - Struktury klas gry
   - Offsety pamięci dla konkretnych wartości
   - Generowanie skryptów Frida do hooków
   - Analizę funkcji IL2CPP

3. Przykładowe pytania:
   ```
   "Gdzie w pamięci znajduje się liczba zasobów gracza?"
   "Jak zhookować funkcję zakupu w sklepie?"
   "Jakie są struktury jednostek w grze?"
   ```

## Następne Kroki

1. ✅ Wydobądź libil2cpp.so i global-metadata.dat
2. ✅ Przeanalizuj pliki z Il2CppDumper
3. ✅ Użyj ChatGPT 5 do zrozumienia struktur
4. ✅ Uruchom Memory Reader do monitorowania RAM
5. ✅ Twórz custom hooki dla konkretnych funkcji

## Wsparcie

Jeśli masz problemy:
1. Sprawdź sekcję "Rozwiązywanie Problemów" powyżej
2. Otwórz issue na GitHub
3. Zapytaj ChatGPT 5 o pomoc
4. Sprawdź logi: `adb logcat`

---

**Powodzenia z botem Rise of Kingdoms!** 🎮🤖
