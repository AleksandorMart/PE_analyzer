import os
import sys
import pandas as pd
import joblib
import argparse
from feature_extractor import extract_features

# Объявляем функцию проверки файла
def is_pe_file(filepath: str) -> bool:
    try:
        with open(filepath, 'rb') as f:
            magic_bytes = f.read(2)
            return magic_bytes == b'MZ'
    except (IOError, PermissionError, OSError):
        return False


# Объявляем функцию для классификации одного файла с использованием загруженных артефактов
def classify_file(file_path: str, degree_suspicion: float, scaler, models):
    print(f"\nАнализ: {os.path.basename(file_path)}")
    
    try:
        features_dict = extract_features(file_path)
    except Exception as e:
        print(f"Пропуск: Ошибка извлечения признаков - {e}")
        return

    if not features_dict:
        print("Пропуск: Функция вернула пустой результат.")
        return

    X_new = pd.DataFrame([features_dict])
    X_new = X_new.apply(pd.to_numeric, errors='coerce')
    X_new.fillna(0, inplace=True)
    X_new_scaled = scaler.transform(X_new)

    threshold = 1.0 - degree_suspicion
    for name, model in models.items():
        prob = float(model.predict_proba(X_new_scaled)[0][1])
        prediction = "Malware" if prob >= threshold else "Benign"
        print(f"  {name} -> {prediction} (Prob: {prob:.4f})")

# Объявляем главную функцию, инкапсулирующую логику загрузки, парсинга аргументов и запуска анализа
def main():
    parser = argparse.ArgumentParser(description="Классификатор PE-файлов (поддерживает файл или папку)")
    parser.add_argument("path", type=str, help="Путь к PE-файлу или директории с файлами для анализа")
    parser.add_argument("degree_suspicion", type=float, help="Степень подозрительности (0.0 - 1.0, чем выше, тем строже порог)")
    args = parser.parse_args()

    if not 0.0 <= args.degree_suspicion <= 1.0:
        print("Ошибка: degree_suspicion должен быть числом от 0.0 до 1.0")
        sys.exit(1)

    if not os.path.exists(args.path):
        print(f"Ошибка: Путь '{args.path}' не найден.")
        sys.exit(1)

    models_dir = "saved_models"
    if not os.path.exists(models_dir):
        print(f"Ошибка: Директория '{models_dir}' не найдена. Сначала запустите скрипт обучения.")
        sys.exit(1)

    print(f"Загрузка артефактов из '{models_dir}'...")
    scaler = joblib.load(os.path.join(models_dir, "scaler.pkl"))
    models = {}
    for filename in os.listdir(models_dir):
        full_path = os.path.join(models_dir, filename)
        if filename == "scaler.pkl":
            continue
        if filename.endswith(".pkl"):
            model_name = filename.replace(".pkl", "")
            models[model_name] = joblib.load(full_path)
    print(f"Загружено {len(models)} моделей.\n")

    target_files = []
    if os.path.isfile(args.path):
        if is_pe_file(args.path):
            target_files.append(args.path)
    elif os.path.isdir(args.path):
        for root, _, files in os.walk(args.path):
            for fname in files:
                full_path = os.path.join(root, fname)
                if is_pe_file(full_path):
                    target_files.append(full_path)
    else:
        print("Ошибка: Указанный путь не является файлом или директорией.")
        sys.exit(1)

    print(f"Найдено {len(target_files)} файлов для анализа.")
    for f_path in target_files:
        classify_file(f_path, args.degree_suspicion, scaler, models)

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Использование: python main_app.py <путь_к_PE_файлу> <степень подозрительности>")
    else:
        main()