# build_dataset.py
import os
import pandas as pd
from feature_extractor import extract_features

# --- КОНСТАНТЫ КОНФИГУРАЦИИ ---
BENIGN_DIR = "data/benign"   # Папка с чистыми файлами
MALWARE_DIR = "data/malware" # Папка с вредоносными файлами
OUTPUT_CSV = "pe_dataset.csv"

# --- Логика сбора ---
def collect_features_from_dir(directory, label):
    records = []
    if not os.path.exists(directory):
        print(f"Папка не найдена: {directory}")
        return records
    
    for filename in os.listdir(directory):
        filepath = os.path.join(directory, filename)
        if not os.path.isfile(filepath):
            continue
        try:
            features = extract_features(filepath)
            if features:
                features['Label'] = label
                records.append(features)
        except Exception as e:
            print(f"Ошибка обработки {filename}: {e}")
            continue
        
    return records

# --- Сохранение разметки ---
def create_csv():
    # --- ГЛАВНЫЙ ЦИКЛ ---
    all_data = []
    all_data.extend(collect_features_from_dir(BENIGN_DIR, 0))   # 0 = легитимный
    all_data.extend(collect_features_from_dir(MALWARE_DIR, 1))  # 1 = вредоносный

    # --- СОХРАНЕНИЕ ---
    if all_data:
        df = pd.DataFrame(all_data)
        df.to_csv(OUTPUT_CSV, index=False)
        print(f"Датасет сохранён: {OUTPUT_CSV}")
        print(f"Всего записей: {len(df)}")
        print(df.head())
    else:
        print("Не удалось найти или обработать файлы в указанных папках.")


# Точка входа
if __name__ == "__main__":
    create_csv()