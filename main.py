#!/usr/bin/env python3
"""
Main entry point for Rise of Kingdoms Bot
Provides menu-driven interface for all bot functions
"""

import sys
import os
from colorama import Fore, Style, init

init(autoreset=True)

# Import modules
from frida_setup import test_connection
from extract_il2cpp import IL2CPPExtractor
from extract_metadata import MetadataExtractor
from memory_reader import MemoryReader


def print_banner():
    """Print application banner"""
    banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║        Rise of Kingdoms - Memory Reading Bot                ║
║                                                              ║
║        Frida 17.3.2 - VirtualBox Android                    ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)


def print_menu():
    """Print main menu"""
    menu = f"""
{Fore.YELLOW}Main Menu:{Style.RESET_ALL}
{Fore.GREEN}1.{Style.RESET_ALL} Test Frida Connection
{Fore.GREEN}2.{Style.RESET_ALL} Extract libil2cpp.so
{Fore.GREEN}3.{Style.RESET_ALL} Extract global-metadata.dat
{Fore.GREEN}4.{Style.RESET_ALL} Extract Both (libil2cpp.so + metadata)
{Fore.GREEN}5.{Style.RESET_ALL} Start Memory Reader Bot
{Fore.GREEN}6.{Style.RESET_ALL} Show Extracted Files
{Fore.GREEN}0.{Style.RESET_ALL} Exit

{Fore.CYAN}Enter your choice:{Style.RESET_ALL} """
    return input(menu)


def show_extracted_files():
    """Show information about extracted files"""
    import config
    
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Extracted Files:")
    print(f"{Fore.CYAN}{'='*60}\n")
    
    files_to_check = [
        (config.LIBIL2CPP_OUTPUT, "libil2cpp.so"),
        (config.METADATA_OUTPUT, "global-metadata.dat")
    ]
    
    found_any = False
    for filepath, name in files_to_check:
        if os.path.exists(filepath):
            size = os.path.getsize(filepath)
            print(f"{Fore.GREEN}[+] {name}:")
            print(f"{Fore.GREEN}    Path: {filepath}")
            print(f"{Fore.GREEN}    Size: {size:,} bytes ({size / 1024 / 1024:.2f} MB)\n")
            found_any = True
    
    if not found_any:
        print(f"{Fore.YELLOW}[!] No files have been extracted yet.")
        print(f"{Fore.YELLOW}[!] Use options 2, 3, or 4 to extract files.\n")
    else:
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}[*] These files can be used with:")
        print(f"{Fore.YELLOW}    - Il2CppDumper (https://github.com/Perfare/Il2CppDumper)")
        print(f"{Fore.YELLOW}    - Il2CppInspector (https://github.com/djkaty/Il2CppInspector)")
        print(f"{Fore.YELLOW}    - Ghidra with IL2CPP analyzer")
        print(f"{Fore.CYAN}{'='*60}\n")


def extract_both():
    """Extract both libil2cpp.so and global-metadata.dat"""
    print(f"\n{Fore.CYAN}{'='*60}")
    print(f"{Fore.CYAN}Extracting Both Files")
    print(f"{Fore.CYAN}{'='*60}\n")
    
    # Extract libil2cpp.so
    print(f"{Fore.YELLOW}[*] Step 1: Extracting libil2cpp.so...")
    il2cpp_extractor = IL2CPPExtractor()
    il2cpp_success = il2cpp_extractor.extract()
    
    if not il2cpp_success:
        print(f"{Fore.RED}[-] Failed to extract libil2cpp.so")
        return False
    
    print(f"\n{Fore.YELLOW}[*] Step 2: Extracting global-metadata.dat...")
    metadata_extractor = MetadataExtractor()
    metadata_success = metadata_extractor.extract()
    
    if not metadata_success:
        print(f"{Fore.RED}[-] Failed to extract global-metadata.dat")
        return False
    
    print(f"\n{Fore.GREEN}{'='*60}")
    print(f"{Fore.GREEN}[+] Both files extracted successfully!")
    print(f"{Fore.GREEN}{'='*60}\n")
    
    return True


def main():
    """Main application loop"""
    print_banner()
    
    while True:
        try:
            choice = print_menu()
            
            if choice == '1':
                print(f"\n{Fore.CYAN}Testing Frida Connection...")
                print(f"{Fore.CYAN}{'='*60}\n")
                test_connection()
                input(f"\n{Fore.YELLOW}Press Enter to continue...")
                
            elif choice == '2':
                print(f"\n{Fore.CYAN}Extracting libil2cpp.so...")
                print(f"{Fore.CYAN}{'='*60}\n")
                extractor = IL2CPPExtractor()
                extractor.extract()
                input(f"\n{Fore.YELLOW}Press Enter to continue...")
                
            elif choice == '3':
                print(f"\n{Fore.CYAN}Extracting global-metadata.dat...")
                print(f"{Fore.CYAN}{'='*60}\n")
                extractor = MetadataExtractor()
                extractor.extract()
                input(f"\n{Fore.YELLOW}Press Enter to continue...")
                
            elif choice == '4':
                extract_both()
                input(f"\n{Fore.YELLOW}Press Enter to continue...")
                
            elif choice == '5':
                print(f"\n{Fore.CYAN}Starting Memory Reader Bot...")
                print(f"{Fore.CYAN}{'='*60}\n")
                reader = MemoryReader()
                reader.start_monitoring()
                input(f"\n{Fore.YELLOW}Press Enter to continue...")
                
            elif choice == '6':
                show_extracted_files()
                input(f"\n{Fore.YELLOW}Press Enter to continue...")
                
            elif choice == '0':
                print(f"\n{Fore.GREEN}[+] Goodbye!")
                sys.exit(0)
                
            else:
                print(f"\n{Fore.RED}[-] Invalid choice. Please try again.")
                input(f"\n{Fore.YELLOW}Press Enter to continue...")
                
        except KeyboardInterrupt:
            print(f"\n\n{Fore.YELLOW}[!] Interrupted by user")
            print(f"{Fore.GREEN}[+] Goodbye!")
            sys.exit(0)
        except Exception as e:
            print(f"\n{Fore.RED}[-] Error: {e}")
            input(f"\n{Fore.YELLOW}Press Enter to continue...")


if __name__ == "__main__":
    main()
