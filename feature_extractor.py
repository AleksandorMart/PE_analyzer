import os
import math
import pefile
from typing import Dict, Any
from datetime import datetime, timezone

# Константы для анализа
SUSPICIOUS_APIS = {
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "WriteProcessMemory", "CreateRemoteThread", "NtUnmapViewOfSection", "ZwUnmapViewOfSection",
    "URLDownloadToFile", "InternetOpenUrl", "HttpOpenRequest", "WinHttpOpen",
    "RegSetValueEx", "CreateService", "ShellExecute", "WinExec",
    "GetProcAddress", "LoadLibrary", "LoadLibraryEx",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess"
}

STANDARD_SECTIONS = {
    b".text", b".data", b".rdata", b".bss", b".rsrc", b".reloc",
    b".idata", b".edata", b".tls", b".pdata", b".00cfg", b"CODE", b"DATA"
}

PACKER_SIGS = {b'UPX', b'ASPack', b'.pack', b'MPRESS', b'Themida'}
WRITE_FLAG = 0x80000000
EXEC_FLAG = 0x20000000

def _calc_entropy(data: bytes) -> float:
    """Эффективный расчёт энтропии Шеннона через фиксированный массив (быстрее Counter для больших данных)."""
    if not data:
        return 0.0
    counter = [0] * 256
    for byte in data:
        counter[byte] += 1
    length = len(data)
    entropy = 0.0
    for count in counter:
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    return entropy

def extract_features(filepath: str) -> Dict[str, Any]:
    """
    Извлекает числовые признаки из PE-файла для ML-классификации (malware vs benign).
    Возвращает словарь с ~30 признаками (int/float).
    """
    if not os.path.isfile(filepath):
        raise FileNotFoundError(f"Файл не найден: {filepath}")

    try:
        with open(filepath, 'rb') as f:
            raw_data = f.read()
        pe = pefile.PE(filepath, fast_load=True)
        pe.parse_data_directories()
    except pefile.PEFormatError as e:
        raise ValueError(f"Файл не является валидным PE: {e}")
    except Exception as e:
        raise RuntimeError(f"Ошибка чтения файла: {e}")

    features: Dict[str, Any] = {}
    oh = pe.OPTIONAL_HEADER
    fh = pe.FILE_HEADER

    try:
        # 1. Базовые метаданные
        features['file_size'] = os.path.getsize(filepath)
        features['num_sections'] = fh.NumberOfSections
        features['machine_type'] = fh.Machine
        features['timestamp'] = fh.TimeDateStamp
        features['subsystem'] = oh.Subsystem
        features['file_characteristics'] = fh.Characteristics

        # 2. Энтропия (глобальная и по секциям)
        features['file_entropy'] = round(_calc_entropy(raw_data), 4)
        
        sec_entropies = []
        for sec in pe.sections:
            try:
                sec_data = sec.get_data()
                sec_entropies.append(_calc_entropy(sec_data))
            except Exception:
                sec_entropies.append(0.0)
                
        if sec_entropies:
            features['section_entropy_mean'] = round(sum(sec_entropies) / len(sec_entropies), 4)
            features['section_entropy_max'] = round(max(sec_entropies), 4)
            features['section_entropy_min'] = round(min(sec_entropies), 4)
            features['section_entropy_std'] = round(
                (sum((e - features['section_entropy_mean'])**2 for e in sec_entropies) / len(sec_entropies))**0.5, 4
            )
            features['high_entropy_sections_count'] = sum(1 for e in sec_entropies if e > 7.0)
        else:
            features['section_entropy_mean'] = 0.0
            features['section_entropy_max'] = 0.0
            features['section_entropy_min'] = 0.0
            features['section_entropy_std'] = 0.0
            features['high_entropy_sections_count'] = 0

        # 3. Импорт/Экспорт/Delay Import
        imports_entry = getattr(pe, 'DIRECTORY_ENTRY_IMPORT', [])
        features['num_imports'] = sum(len(entry.imports) for entry in imports_entry)
        features['dll_count'] = len(imports_entry)
        
        imports_by_ordinal = 0
        suspicious_api_count = 0
        if imports_entry:
            for entry in imports_entry:
                for imp in entry.imports:
                    if imp.import_by_ordinal:
                        imports_by_ordinal += 1
                    elif imp.name:
                        if imp.name.decode('utf-8', errors='ignore') in SUSPICIOUS_APIS:
                            suspicious_api_count += 1
                            
        features['imports_by_ordinal_count'] = imports_by_ordinal
        features['suspicious_api_count'] = suspicious_api_count
        features['num_exports'] = len(getattr(pe.DIRECTORY_ENTRY_EXPORT, 'symbols', [])) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
        features['num_delay_imports'] = sum(len(imp.imports) for imp in getattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT', []))

        # 4. Заголовки и размеры
        features['address_of_entry_point'] = oh.AddressOfEntryPoint
        features['size_of_code'] = oh.SizeOfCode
        features['size_of_image'] = oh.SizeOfImage
        features['size_of_headers'] = oh.SizeOfHeaders
        features['checksum_stored'] = oh.CheckSum
        features['code_to_image_ratio'] = round(oh.SizeOfCode / oh.SizeOfImage, 4) if oh.SizeOfImage > 0 else 0.0
        
        raw_sizes = [s.SizeOfRawData for s in pe.sections]
        virtual_sizes = [s.Misc_VirtualSize for s in pe.sections]
        features['section_raw_size_mean'] = round(sum(raw_sizes) / len(raw_sizes), 4) if raw_sizes else 0.0
        features['section_virtual_size_mean'] = round(sum(virtual_sizes) / len(virtual_sizes), 4) if virtual_sizes else 0.0

        # 5. Защита и флаги безопасности
        features['aslr_enabled'] = 1 if (oh.DllCharacteristics & 0x0040) else 0
        features['dep_enabled'] = 1 if (oh.DllCharacteristics & 0x0100) else 0
        features['has_signature'] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_SECURITY') else 0
        features['checksum_mismatch'] = 1 if (oh.CheckSum != 0 and oh.CheckSum != pe.generate_checksum()) else 0
        
        features['has_wx_section'] = 0
        for sec in pe.sections:
            if (sec.Characteristics & WRITE_FLAG) and (sec.Characteristics & EXEC_FLAG):
                features['has_wx_section'] = 1
                break

        # 6. Директории и отладка
        features['has_debug_directory'] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG') else 0
        features['has_resource_directory'] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') else 0
        features['has_tls_directory'] = 1 if hasattr(pe, 'DIRECTORY_ENTRY_TLS') else 0
        features['has_relocations'] = 1 if oh.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_BASERELOC']].VirtualAddress != 0 else 0
        
        dir_res = oh.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']]
        features['resource_size'] = dir_res.Size

        # Поиск PDB-путей
        features['has_pdb'] = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_DEBUG'):
            for dbg in pe.DIRECTORY_ENTRY_DEBUG:
                if dbg.struct.Type == pefile.DEBUG_TYPE.get('IMAGE_DEBUG_TYPE_CODEVIEW', 2):
                    try:
                        dbg_data = pe.get_data(dbg.struct.PointerToRawData, dbg.struct.SizeOfData)
                        if b'RSDS' in dbg_data or b'NB10' in dbg_data:
                            features['has_pdb'] = 1
                            break
                    except Exception:
                        pass

        features['has_tls_callbacks'] = 0
        if hasattr(pe, 'DIRECTORY_ENTRY_TLS') and pe.DIRECTORY_ENTRY_TLS.struct.AddressOfCallBacks != 0:
            features['has_tls_callbacks'] = 1

        # 7. Аномалии и продвинутые метрики
        features['overlay_size'] = len(pe.get_overlay() or b'')
        
        try:
            compile_time = datetime.fromtimestamp(fh.TimeDateStamp, tz=timezone.utc)
            age_years = (datetime.now(timezone.utc) - compile_time).total_seconds() / (3600 * 24 * 365.25)
            features['timestamp_age_years'] = round(max(age_years, 0.0), 2)
        except Exception:
            features['timestamp_age_years'] = 0.0

        exec_sec_size = sum(s.Misc_VirtualSize for s in pe.sections if s.Characteristics & EXEC_FLAG)
        features['code_section_ratio'] = round(exec_sec_size / oh.SizeOfImage, 4) if oh.SizeOfImage > 0 else 0.0

        vr_ratios = [s.Misc_VirtualSize / s.SizeOfRawData for s in pe.sections if s.SizeOfRawData > 0]
        features['mean_vr_raw_ratio'] = round(sum(vr_ratios) / len(vr_ratios), 4) if vr_ratios else 0.0

        features['non_standard_section_count'] = sum(
            1 for sec in pe.sections if sec.Name.rstrip(b'\x00') not in STANDARD_SECTIONS
        )
        features['has_packer_signature'] = 1 if any(any(sig in sec.Name for sig in PACKER_SIGS) for sec in pe.sections) else 0

    finally:
        pe.close()

    return features

# Точка входа для самостоятельного тестирования
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Использование: python feature_extractor.py <путь_к_PE_файлу>")
    else:
        feats = extract_features(sys.argv[1])
        if feats:
            for key, value in feats.items():
                print(f"{key}: {value}")
