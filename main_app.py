import os
import sys
import pandas as pd
import numpy as np
import joblib
import argparse
from feature_extractor import extract_features

# Объявляем основную функцию, инкапсулирующую логику инференса
def file_classification(file_path: str, degree_suspicion: float):  
    if not os.path.exists(file_path):
        print(f"Ошибка: Файл '{file_path}' не найден.")
        sys.exit(1)

    models_dir = "saved_models"
    if not os.path.exists(models_dir):
        print(f"Ошибка: Директория '{models_dir}' не найдена. Сначала запустите скрипт обучения.")
        sys.exit(1)

    print(f"Загрузка артефактов из '{models_dir}'...")
    scaler = joblib.load(os.path.join(models_dir, "scaler.pkl"))
    #УЗНАТЬ НАХУЯ SCALER.PKL
    models = {}
    for filename in os.listdir(models_dir):
        full_path = os.path.join(models_dir, filename)
        if filename == "scaler.pkl":
            continue
        if filename.endswith(".pkl"):
            model_name = filename.replace(".pkl", "")
            models[model_name] = joblib.load(full_path)

    print(f"Загружено {len(models)} моделей.\n")

    print(f"Извлечение признаков из: {file_path}")
    features_dict = extract_features(file_path)
    if not features_dict:
        print("Ошибка: Не удалось извлечь признаки. Файл повреждён или не является PE.")
        sys.exit(1)

    X_new = pd.DataFrame([features_dict])
    X_new = X_new.apply(pd.to_numeric, errors='coerce')
    X_new.fillna(0, inplace=True)
    X_new_scaled = scaler.transform(X_new)

    print("\nРезультаты классификации:")
    for name, model in models.items():
        prob = float(model.predict_proba(X_new_scaled)[0][1])

        prediction = "Malware" if prob >=1-degree_suspicion else "Benign"
        print(f"{name} - {prediction} - {prob:.5}")

if __name__ == "__main__":
    import sys
    parser = argparse.ArgumentParser(description="Классификатор PE-файлов на основе обученных ML-моделей")
    parser.add_argument("file_path", type=str, help="Путь к анализируемому PE-файлу")
    parser.add_argument("degree_suspicion", type=float, help="Степень подозрительности классификатора")
    args = parser.parse_args()
    if len(sys.argv) != 3:
        print("Использование: python main_app.py <путь_к_PE_файлу> <степень подозрительности>")
    else:
        file_classification(args.file_path, args.degree_suspicion)