import pefile
import sys

def analyze_pe(file_path):
    """Загружает PE-файл и выводит его базовую информацию"""
    try:
        # Загружаем файл
        pe = pefile.PE(file_path)

        print(f"Анализ файла: {file_path}\n")
        print("--- DOS-заголовок ---")
        print(f"e_magic (MZ signature): {hex(pe.DOS_HEADER.e_magic)}")
        print(f"e_lfanew (offset to PE header): {hex(pe.DOS_HEADER.e_lfanew)}")

        print("\n--- FILE_HEADER ---")
        print(f"Machine: {hex(pe.FILE_HEADER.Machine)}")
        print(f"NumberOfSections: {pe.FILE_HEADER.NumberOfSections}")
        print(f"TimeDateStamp: {pe.FILE_HEADER.TimeDateStamp}")
        print(f"Characteristics: {hex(pe.FILE_HEADER.Characteristics)}")

        print("\n--- OPTIONAL_HEADER ---")
        print(f"Magic: {hex(pe.OPTIONAL_HEADER.Magic)}")
        print(f"AddressOfEntryPoint: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"ImageBase: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
        print(f"SectionAlignment: {hex(pe.OPTIONAL_HEADER.SectionAlignment)}")
        print(f"FileAlignment: {hex(pe.OPTIONAL_HEADER.FileAlignment)}")
        print(f"SizeOfImage: {hex(pe.OPTIONAL_HEADER.SizeOfImage)}")
        print(f"SizeOfHeaders: {hex(pe.OPTIONAL_HEADER.SizeOfHeaders)}")
        print(f"Subsystem: {pe.OPTIONAL_HEADER.Subsystem}")
        print(f"DllCharacteristics: {hex(pe.OPTIONAL_HEADER.DllCharacteristics)}")

        print("\n--- Секции ---")
        for section in pe.sections:
            print(f"Имя: {section.Name.decode().rstrip(chr(0)):<8} | "
                  f"VirtualAddress: {hex(section.VirtualAddress):<8} | "
                  f"VirtualSize: {hex(section.Misc_VirtualSize):<8} | "
                  f"RawSize: {hex(section.SizeOfRawData):<8}")

        # ... (остальная информация — для следующего шага)

        print("\n--- Импортируемые функции (первые 5) ---")
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT[:5]:
                print(f"  DLL: {entry.dll.decode()}")
                for imp in entry.imports[:5]:
                    if imp.name:
                        print(f"    Функция: {imp.name.decode()}")
        else:
            print("  Таблица импорта не найдена.")

        pe.close()

    except FileNotFoundError:
        print(f"Ошибка: Файл '{file_path}' не найден.")
    except pefile.PEFormatError:
        print(f"Ошибка: Файл '{file_path}' не является корректным PE-файлом.")
    except Exception as e:
        print(f"Произошла непредвиденная ошибка: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Использование: python pe_reader.py <путь_к_PE_файлу>")
    else:
        analyze_pe(sys.argv[1])