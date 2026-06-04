import os
import warnings
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import confusion_matrix, roc_curve, auc, accuracy_score
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, ExtraTreesClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
import joblib
import json

# Отключаем вывод предупреждений, чтобы не загромождать консоль во время выполнения
warnings.filterwarnings('ignore')

# --- ЗАГРУЗКА И ПОДГОТОВКА ДАННЫХ ---
df = pd.read_csv('pe_dataset.csv')
X = df.drop('Label', axis=1)
y = df['Label']

X = X.apply(pd.to_numeric, errors='coerce')
X.replace([np.inf, -np.inf], np.nan, inplace=True)
X.fillna(X.median(), inplace=True)

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# --- ОПРЕДЕЛЕНИЕ МОДЕЛЕЙ ---
models = {}
models['RandomForest'] = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
models['GradientBoosting'] = GradientBoostingClassifier(n_estimators=100, random_state=42)
models['LogisticRegression'] = LogisticRegression(max_iter=1000, random_state=42)
models['SVC'] = SVC(probability=True, random_state=42)
models['ExtraTrees'] = ExtraTreesClassifier(n_estimators=100, random_state=42, n_jobs=-1)

# --- ПОДГОТОВКА ДИРЕКТОРИЙ ДЛЯ СОХРАНЕНИЯ ---
os.makedirs('saved_models', exist_ok=True)
os.makedirs('plots', exist_ok=True)

# --- ОБУЧЕНИЕ, ОЦЕНКА И СБОР РЕЗУЛЬТАТОВ ---
model_results = {}
plt.figure(figsize=(10, 8))
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random Guess')

roc_data = {}

for name, model in models.items():
    print(f"\nОбучение модели: {name}...")
    model.fit(X_train_scaled, y_train)
    y_prob = model.predict_proba(X_test_scaled)[:, 1]

    y_pred = (y_prob >= 0.5).astype(int)
    acc = accuracy_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    fpr, tpr, _ = roc_curve(y_test, y_prob)
    roc_auc = auc(fpr, tpr)

    model_results[name] = {
        'model': model,
        'accuracy': acc,
        'roc_auc': roc_auc,
        'confusion_matrix': cm.tolist()
    }

    # --- СОХРАНЕНИЕ МАТРИЦЫ ОШИБОК ДЛЯ ТЕКУЩЕЙ МОДЕЛИ ---
    plt.figure(figsize=(6, 5))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Benign', 'Malware'], yticklabels=['Benign', 'Malware'])
    plt.title(f'Confusion Matrix - {name}')
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.tight_layout()
    cm_filename = f'plots/confusion_matrix_{name}.png'
    plt.savefig(cm_filename, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"Матрица ошибок сохранена: {cm_filename}")

    print(f"Матрица ошибок ({name}):\n{cm}")
    print(f"Accuracy: {acc:.4f} | ROC-AUC: {roc_auc:.4f}")

    # Добавляем ROC-кривую модели на общее окно графика
    plt.plot(fpr, tpr, lw=2, label=f'{name} (AUC = {roc_auc:.3f})')
    
    # Сохраняем данные ROC для последующего зум-графика
    roc_data[name] = {'fpr': fpr, 'tpr': tpr, 'auc': roc_auc}

# --- ФИНАЛИЗАЦИЯ И СОХРАНЕНИЕ ГРАФИКА ROC ---
plt.xlim([0.0, 1.0])
plt.ylim([0.0, 1.05])
plt.xlabel('False Positive Rate')
plt.ylabel('True Positive Rate')
plt.title('ROC Curves Comparison for All Models')
plt.legend(loc="lower right")
plt.grid(True)
plt.tight_layout()
roc_filename = 'plots/roc_curves_comparison.png'
plt.savefig(roc_filename, dpi=300, bbox_inches='tight')
print(f"ROC-график сохранён: {roc_filename}")
plt.close()

# --- СОХРАНЕНИЕ ЗУМ-ОБЛАСТИ ROC (0 <= FPR <= 0.15, 0.85 <= TPR <= 1.05) ---
plt.figure(figsize=(10, 8))
for name, data in roc_data.items():
    plt.plot(data['fpr'], data['tpr'], lw=2, label=f"{name} (AUC = {data['auc']:.3f})")
plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random Guess')
plt.xlim([0.0, 0.15])
plt.ylim([0.85, 1.05])
plt.xlabel('False Positive Rate (Zoomed: 0.0 - 0.15)')
plt.ylabel('True Positive Rate (Zoomed: 0.85 - 1.0)')
plt.title('ROC Curves - Critical Region (Low FPR, High TPR)')
plt.legend(loc="lower right", fontsize=9)
plt.grid(True, alpha=0.3)
plt.tight_layout()
zoom_filename = 'plots/roc_curves_zoom_critical_region.png'
plt.savefig(zoom_filename, dpi=300, bbox_inches='tight')
print(f"Zoom ROC-график сохранён: {zoom_filename}")
plt.close()

# --- СОХРАНЕНИЕ МОДЕЛЕЙ И МЕТРИК ---
for name, data in model_results.items():
    joblib.dump(data['model'], f'saved_models/{name}.pkl')
    with open(f'saved_models/{name}_metrics.json', 'w') as f:
        json.dump({k: v for k, v in data.items() if k != 'model'}, f, indent=2)

joblib.dump(scaler, 'saved_models/scaler.pkl')
print("\nВсе модели, метрики и scaler успешно сохранены в папку 'saved_models/'.")
print(f"Графики и матрицы ошибок сохранены в папку 'plots/'.")
print(f"Итоговый словарь 'model_results' содержит {len(model_results)} моделей с полными характеристиками.")