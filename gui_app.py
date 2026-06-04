import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import threading
import queue
import os
import sys
import pandas as pd
import joblib
from PIL import Image, ImageTk
from feature_extractor import extract_features
import datetime

# Объявляем основной класс приложения, инкапсулирующий всю логику интерфейса
class PEAnalyzerGUI:
    
    # Инициализируем объект GUI при запуске
    def __init__(self):
        self.root = tk.Tk()  # Создаём главное окно приложения
        self.root.title("PE Analyzer")  # Устанавливаем заголовок окна
        self.root.geometry("900x700")  # Задаём начальные размеры окна
        self.root.resizable(True, True)  # Разрешаем изменение размеров окна пользователем
        self.msg_queue = queue.Queue()  # Создаём потокобезопасную очередь для передачи логов из рабочего потока в GUI
        self.scaler = None  # Инициализируем переменную для объекта стандартизации (пока None)
        self.models = {}  # Создаём пустой словарь для хранения загруженных классификаторов
        self.models_loaded = threading.Event()  # Создаём флаг синхронизации для ожидания загрузки моделей
        self.photo_refs = []  # Создаём список для хранения ссылок на изображения, чтобы сборщик мусора не удалял их
        self.session_results = {}  # Инициализируем словарь для хранения структурированных результатов по степеням подозрительности
        self._setup_ui()  # Вызываем метод построения интерфейса
        self._load_models_async()  # Запускаем асинхронную загрузку моделей в фоне
        self._poll_queue()  # Запускаем цикл опроса очереди сообщений для обновления текстового поля
        self.root.mainloop()  # Запускаем главный цикл обработки событий интерфейса

    # Метод для создания и компоновки всех виджетов интерфейса
    def _setup_ui(self):
        self.notebook = ttk.Notebook(self.root)  # Создаём компонент вкладок для разделения функционала
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)  # Размещаем вкладки в окне с отступами и растяжением
        self.tab_classify = ttk.Frame(self.notebook)  # Создаём фрейм для первой вкладки (классификация)
        self.notebook.add(self.tab_classify, text="1. Классификация файлов")  # Добавляем первую вкладку в ноутбук
        self.tab_analytics = ttk.Frame(self.notebook)  # Создаём фрейм для второй вкладки (аналитика)
        self.notebook.add(self.tab_analytics, text="2. Аналитика")  # Добавляем вторую вкладку в ноутбук
        self._build_classify_tab()  # Вызываем метод построения содержимого первой вкладки
        self._build_analytics_tab()  # Вызываем метод построения содержимого второй вкладки

    # Метод для компоновки элементов вкладки классификации
    def _build_classify_tab(self):
        path_frame = ttk.Frame(self.tab_classify)  # Создаём контейнер для элементов выбора пути
        path_frame.pack(fill=tk.X, padx=5, pady=5)  # Упаковываем контейнер по горизонтали с отступами
        self.path_var = tk.StringVar()  # Создаём строковую переменную для хранения пути
        self.path_entry = ttk.Entry(path_frame, textvariable=self.path_var)  # Создаём поле ввода пути
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))  # Размещаем поле слева с растяжением
        
        btns_frame = ttk.Frame(path_frame)  # Создаем отдельный фрейм для размещения двух кнопок
        btns_frame.pack(side=tk.RIGHT)  # Упаковываем фрейм кнопок справа от поля ввода

        self.file_btn = ttk.Button(btns_frame, text="Выбрать файл", command=self._browse_file)  # Кнопка для выбора одного PE-файла
        self.file_btn.pack(side=tk.LEFT, padx=2)  # Размещаем кнопку с небольшим отступом

        self.dir_btn = ttk.Button(btns_frame, text="Выбрать папку", command=self._browse_dir)  # Кнопка для выбора директории
        self.dir_btn.pack(side=tk.LEFT, padx=2)  # Размещаем кнопку рядом с первой
        
        ctrl_frame = ttk.Frame(self.tab_classify)  # Создаём контейнер для элементов управления
        ctrl_frame.pack(fill=tk.X, padx=5, pady=5)  # Упаковываем контейнер управления
        ttk.Label(ctrl_frame, text="Степень подозрительности (0.0-1.0):").pack(side=tk.LEFT)  # Создаём и размещаем подпись
        self.suspicion_var = tk.StringVar(value="0.5")  # Создаём переменную для степени подозрительности со значением по умолчанию
        self.suspicion_entry = ttk.Entry(ctrl_frame, textvariable=self.suspicion_var, width=5)  # Создаём поле ввода параметра
        self.suspicion_entry.pack(side=tk.LEFT, padx=(5, 20))  # Размещаем поле с отступом
        self.classify_btn = ttk.Button(ctrl_frame, text="Классифицировать", command=self._start_classification)  # Создаём кнопку запуска анализа
        self.classify_btn.pack(side=tk.LEFT)  # Упаковываем кнопку запуска
        self.report_btn = ttk.Button(ctrl_frame, text="Создать отчёт", command=self._create_report)  # Создаём кнопку отчёта (заглушка)
        self.report_btn.pack(side=tk.LEFT, padx=(10, 0))  # Размещаем кнопку отчёта
        res_frame = ttk.Frame(self.tab_classify)  # Создаём контейнер для поля вывода результатов
        res_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)  # Упаковываем контейнер с растяжением
        self.result_text = tk.Text(res_frame, wrap=tk.WORD, state=tk.DISABLED)  # Создаём многострочное поле вывода
        scrollbar = ttk.Scrollbar(res_frame, command=self.result_text.yview)  # Создаём вертикальную полосу прокрутки
        self.result_text.configure(yscrollcommand=scrollbar.set)  # Связываем поле прокрутки с текстовым виджетом
        self.result_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)  # Размещаем текстовое поле слева с растяжением
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)  # Размещаем полосу прокрутки справа
        self.notebook.bind("<<NotebookTabChanged>>", self._on_tab_changed)  # Привязываем обработчик смены вкладки для обновления аналитики

    # Метод для компоновки элементов вкладки аналитики
    def _build_analytics_tab(self):
        self.analytics_canvas = tk.Canvas(self.tab_analytics)  # Создаём холст для прокрутки изображений
        self.scrollbar_y = ttk.Scrollbar(self.tab_analytics, orient=tk.VERTICAL, command=self.analytics_canvas.yview)  # Создаём вертикальный скроллбар
        self.analytics_frame = ttk.Frame(self.analytics_canvas)  # Создаём контейнер внутри холста для размещения графиков
        self.analytics_frame.bind("<Configure>", lambda e: self.analytics_canvas.configure(scrollregion=self.analytics_canvas.bbox("all")))  # Обновляем область прокрутки при изменении размера контейнера
        self.analytics_canvas.create_window((0, 0), window=self.analytics_frame, anchor="nw")  # Размещаем контейнер в холсте
        self.analytics_canvas.configure(yscrollcommand=self.scrollbar_y.set)  # Связываем холст с вертикальным скроллбаром
        self.analytics_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)  # Упаковываем холст слева
        self.scrollbar_y.pack(side=tk.RIGHT, fill=tk.Y)  # Упаковываем скроллбар справа
        
        self.analytics_canvas.bind("<Enter>", self._on_canvas_enter)  # Привязываем событие наведения мыши на область холста
        self.analytics_canvas.bind("<Leave>", self._on_canvas_leave)  # Привязываем событие ухода мыши с области холста
        
        self.refresh_analytics_btn = ttk.Button(self.tab_analytics, text="Обновить графики", command=self._refresh_analytics)  # Создаём кнопку ручного обновления
        self.refresh_analytics_btn.pack(pady=10)  # Упаковываем кнопку обновления с отступом
        self._refresh_analytics()  # Выполняем первоначальную загрузку изображений

    # Метод активации прокрутки при входе мыши в область графиков
    def _on_canvas_enter(self, event):
        self.analytics_canvas.bind_all("<MouseWheel>", self._on_mousewheel)  # Включаем колесо мыши (Windows/Mac)
        self.analytics_canvas.bind_all("<Button-4>", self._on_mousewheel)  # Включаем кнопки Linux (вверх)
        self.analytics_canvas.bind_all("<Button-5>", self._on_mousewheel)  # Включаем кнопки Linux (вниз)

    # Метод деактивации прокрутки при уходе мыши
    def _on_canvas_leave(self, event):
        self.analytics_canvas.unbind_all("<MouseWheel>")  # Отключаем колесо мыши
        self.analytics_canvas.unbind_all("<Button-4>")  # Отключаем кнопки Linux
        self.analytics_canvas.unbind_all("<Button-5>")  # Отключаем кнопки Linux

    # Обработчик события вращения колеса мыши
    def _on_mousewheel(self, event):
        if event.num == 4 or event.delta > 0:  # Определяем прокрутку вверх
            self.analytics_canvas.yview_scroll(-1, "units")  # Сдвигаем контент вверх
        elif event.num == 5 or event.delta < 0:  # Определяем прокрутку вниз
            self.analytics_canvas.yview_scroll(1, "units")  # Сдвигаем контент вниз
    
    # Метод вызова диалога выбора конкретного файла
    def _browse_file(self):
        path = filedialog.askopenfilename(filetypes=[("PE Files", "*.exe;*.dll;*.sys;*.scr"), ("All Files", "*.*")])  # Открываем окно с фильтром для исполняемых файлов
        if path: self.path_var.set(path)  # Устанавливаем выбранный путь в переменную

    # Метод вызова диалога выбора директории
    def _browse_dir(self):
        path = filedialog.askdirectory()  # Открываем окно выбора папки
        if path: self.path_var.set(path)  # Устанавливаем выбранный путь в переменную
    
    # Метод безопасной отправки логов из любого потока в очередь GUI
    def _safe_log(self, message: str):
        self.msg_queue.put(message)  # Помещаем сообщение в потокобезопасную очередь

    # Метод периодического опроса очереди и вывода сообщений в интерфейс
    def _poll_queue(self):
        try:  # Пытаемся получить сообщение без блокировки
            msg = self.msg_queue.get_nowait()  # Извлекаем сообщение из очереди
            self.result_text.config(state=tk.NORMAL)  # Временно включаем редактирование текстового поля
            self.result_text.insert(tk.END, msg + "\n")  # Добавляем сообщение в конец поля
            self.result_text.config(state=tk.DISABLED)  # Возвращаем поле в режим только для чтения
            self.result_text.see(tk.END)  # Автоматически прокручиваем поле до последней строки
        except queue.Empty:  # Если очередь пуста, пропускаем итерацию
            pass
        self.root.after(100, self._poll_queue)  # Планируем следующий опрос через 100 мс

    # Метод фоновой загрузки моделей и скалера
    def _load_models_async(self):
        threading.Thread(target=self._load_models_worker, daemon=True).start()  # Запускаем загрузку в отдельном демоне-потоке

    # Рабочий поток загрузки артефактов
    def _load_models_worker(self):
        self._safe_log("Загрузка моделей и скалера...")  # Отправляем статус в очередь логов
        try:  # Пытаемся загрузить необходимые файлы
            if not os.path.exists("saved_models"):  # Проверяем наличие директории
                raise FileNotFoundError("Директория 'saved_models' не найдена.")  # Генерируем ошибку при отсутствии
            self.scaler = joblib.load(os.path.join("saved_models", "scaler.pkl"))  # Загружаем объект стандартизации
            for f in os.listdir("saved_models"):  # Перебираем файлы в директории
                full = os.path.join("saved_models", f)  # Формируем полный путь
                if f.endswith(".pkl") and f != "scaler.pkl":  # Фильтруем только файлы моделей
                    self.models[f.replace(".pkl", "")] = joblib.load(full)  # Загружаем модель в словарь
            self.models_loaded.set()  # Устанавливаем флаг успешной загрузки
            self._safe_log(f"Загружено {len(self.models)} моделей. Готово к работе.")  # Логируем успех
        except Exception as e:  # Ловим любые ошибки загрузки
            self._safe_log(f"Ошибка загрузки моделей: {e}")  # Логируем ошибку

    # Метод запуска классификации по кнопке
    def _start_classification(self):
        path = self.path_var.get().strip()  # Получаем и очищаем путь из поля ввода
        if not path:  # Проверяем, что поле не пустое
            messagebox.showwarning("Внимание", "Укажите путь к файлу или папке.")  # Показываем предупреждение
            return  # Прерываем выполнение
        try:  # Пытаемся преобразовать параметр подозрительности
            susp = float(self.suspicion_var.get())  # Парсим значение из строки
        except ValueError:  # Ловим ошибку парсинга числа
            messagebox.showerror("Ошибка", "Степень подозрительности должна быть числом.")  # Показываем ошибку
            return  # Прерываем выполнение
        if not self.models_loaded.is_set():  # Проверяем, загрузились ли модели
            messagebox.showwarning("Ожидание", "Модели ещё загружаются. Подождите...")  # Информируем пользователя
            return  # Прерываем запуск
        self.classify_btn.config(state=tk.DISABLED)  # Блокируем кнопку запуска во избежание повторных нажатий
        threading.Thread(target=self._classification_worker, args=(path, susp), daemon=True).start()  # Запускаем анализ в фоне

    def _classification_worker(self, path: str, susp: float):  # Рабочий поток классификации
        threshold = 1.0 - susp  # Вычисляем пороговое значение вероятности
        target_files = []  # Создаём список файлов для анализа
        if os.path.isfile(path):  # Проверяем тип пути
            if self._is_pe(path): target_files.append(path)  # Добавляем файл только если это PE
            else: self._safe_log(f"'{path}' не является PE-файлом.")  # Логируем пропуск
        elif os.path.isdir(path):  # Проверяем тип пути
            for r, _, fs in os.walk(path):  # Рекурсивно обходим папку
                for f in fs:  # Перебираем файлы
                    fp = os.path.join(r, f)  # Формируем путь
                    if self._is_pe(fp): target_files.append(fp)  # Фильтруем только PE
        else:  # Обрабатываем некорректный тип
            self._safe_log("Путь не является файлом или папкой.")  # Логируем ошибку
            self.root.after(0, lambda: self.classify_btn.config(state=tk.NORMAL))  # Разблокируем кнопку
            return  # Завершаем поток
        if not target_files:  # Проверяем, есть ли файлы для обработки
            self._safe_log("PE-файлы не найдены.")  # Логируем пустой результат
            self.root.after(0, lambda: self.classify_btn.config(state=tk.NORMAL))  # Разблокируем кнопку
            return  # Завершаем поток
        self._safe_log(f"\nНайдено {len(target_files)} файлов. Начинаем анализ. Степень подозрительности {susp}.")  # Логируем старт
        current_results = []  # Создаем список для накопления структурированных результатов текущей сессии
        for fp in target_files:  # Перебираем найденные файлы
            self._safe_log(f"\n{os.path.basename(fp)}")  # Логируем имя файла
            try:  # Пытаемся извлечь признаки
                feats = extract_features(fp)  # Вызываем функцию парсинга
            except Exception as e:  # Ловим ошибки парсинга
                self._safe_log(f"Пропуск: {e}")  # Логируем и продолжаем
                continue  # Переходим к следующему файлу
            if not feats:  # Проверяем результат
                self._safe_log("Пустые признаки.")  # Логируем
                continue  # Переходим дальше
            X = pd.DataFrame([feats])  # Конвертируем в DataFrame
            X = X.apply(pd.to_numeric, errors="coerce")  # Приводим к числам
            X.fillna(0, inplace=True)  # Заполняем пропуски
            Xs = self.scaler.transform(X)  # Масштабируем данные
            file_results = {'file': os.path.basename(fp), 'models': {}}  # Создаем словарь для хранения результатов конкретного файла
            for name, mdl in self.models.items():  # Перебираем модели
                prob = float(mdl.predict_proba(Xs)[0][1])  # Получаем вероятность Malware
                pred = "Malware" if prob >= threshold else "Benign"  # Определяем метку
                self._safe_log(f"  {name} -> {pred} (Вероятность: {prob:.4f})")  # Выводим результат
                file_results['models'][name] = (pred, prob)  # Сохраняем предсказание и вероятность в структуру данных
            current_results.append(file_results)  # Добавляем результаты файла в список текущей сессии
        if susp in self.session_results:  # Проверяем, существуют ли уже результаты для данной степени подозрительности
            self.session_results[susp].extend(current_results)  # Добавляем новые результаты к существующему списку, сохраняя историю проверок
        else:  # Если это первая проверка с таким параметром
            self.session_results[susp] = current_results  # Инициализируем список результатов для новой степени подозрительности
        self._safe_log("\nАнализ завершён.")  # Логируем окончание
        self.root.after(0, lambda: self.classify_btn.config(state=tk.NORMAL))  # Разблокируем кнопку в основном потоке

    # Метод быстрой проверки PE-сигнатуры
    def _is_pe(self, filepath: str) -> bool:
        try:  # Пытаемся открыть файл
            with open(filepath, "rb") as f:  # Открываем в бинарном режиме
                return f.read(2) == b"MZ"  # Возвращаем результат сравнения первых двух байтов
        except:  # Ловим любые ошибки доступа
            return False  # Возвращаем False при недоступности
    
    # Метод создания отчета
    def _create_report(self):
        if not self.session_results:  # Проверяем наличие сохраненных структурированных результатов перед генерацией
            messagebox.showinfo("Информация", "Нет данных для создания отчета. Сначала выполните классификацию.")
            return
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")  # Генерируем метку времени для имени файла
        default_name = f"report_{timestamp}.txt"  # Формируем предлагаемое имя файла
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", initialfile=default_name, filetypes=[("Text files", "*.txt")])  # Открываем диалог сохранения файла
        if not file_path: return  # Если пользователь отменил сохранение, выходим
        header = f"=== ОТЧЕТ ПРОВЕРКИ ===\nДата: {timestamp}\n{'='*30}\n\n"  # Создаем заголовок отчета с параметрами проверки
        try:  # Начинаем блок записи файла
            with open(file_path, "w", encoding="utf-8") as f:  # Открываем выбранный файл для записи
                f.write(header)  # Записываем заголовок и результаты из текстового виджета
                for susp in sorted(self.session_results.keys()):  # Перебираем отсортированные степени подозрительности для создания отдельных таблиц
                    f.write(f"--- Степень подозрительности: {susp} (Порог Malware: {1 - susp:.2f}) ---\n")  # Записываем в файл заголовок секции, указывая текущую степень подозрительности
                    results = self.session_results[susp]  # Извлекаем список результатов проверки файлов, соответствующий именно этой степени подозрительности
                    if not results:  # Проверяем, не пуст ли список результатов (защита от генерации пустых таблиц)
                        continue  # Прерываем текущую итерацию цикла и переходим к обработке следующей степени подозрительности
                    models = list(results[0]['models'].keys())  # Получаем список моделей из первого результата (набор моделей одинаков)
                    t_header = f"{'Файл':<40}" + "".join([f"{m:<20}" for m in models]) + "\n"  # Формируем строку заголовка таблицы: слово "Файл" выровнено по левому краю в 40 символов, за ним следуют названия моделей, каждое выровнено по левому краю в 20 символов
                    f.write(t_header)  # Записываем сформированную строку заголовка в текстовый файл
                    f.write("-" * len(t_header) + "\n")  # Записываем разделительную линию из дефисов, длина которой динамически рассчитывается и точно соответствует длине строки заголовка
                    for res in results:  # Запускаем цикл по каждому словарю с результатами проверки конкретного файла для формирования строк таблицы
                        filename = res['file']  # Получаем исходное имя файла
                        if len(filename) > 40:  # Проверяем, превышает ли длина имени 40 символов
                            filename = filename[:35] + "..."  # Обрезаем до 35 символов и добавляем многоточие
                        row = f"{filename:<40}"  # Формируем строку с выравниванием по левому краю до 40 символов
                        for m in models:  # Запускаем вложенный цикл по списку названий моделей для последовательного заполнения ячеек текущей строки
                            pred, prob = res['models'].get(m, ("N/A", 0.0))  # Извлекаем кортеж (предсказание, вероятность) для текущей модели; если по какой-то причине модель отсутствует в данных, используем значения по умолчанию
                            cell = f"{pred} ({prob:.4f})"  # Формируем строку ячейки в требуемом формате: текстовое предсказание и вероятность, округленная до 4 знаков после запятой
                            row += f"{cell:<20}"  # Добавляем сформированную ячейку к текущей строке, выравнивая её по левому краю и резервируя под неё ровно 20 символов для сохранения табличной структуры
                        f.write(row + "\n")  # Записываем полностью сформированную строку таблицы (имя файла + результаты всех моделей) в файл с переходом на новую строку
                    f.write("\n")  # Добавляем пустую строку после завершения формирования всей таблицы, чтобы визуально отделить её от блока следующей степени подозрительности
            self._safe_log(f"Отчет сохранен: {file_path}")  # Пишем статус сохранения в лог интерфейса
            messagebox.showinfo("Успех", f"Отчет сохранен:\n{file_path}")  # Показываем всплывающее окно об успехе
        except Exception as e:  # Ловим ошибки ввода-вывода
            messagebox.showerror("Ошибка", f"Не удалось сохранить отчет:\n{e}")  # Выводим сообщение об ошибке
    
    # Обработчик события переключения вкладок
    def _on_tab_changed(self, event):
        if self.notebook.tab(self.notebook.select(), "text") == "2. Аналитика":  # Проверяем, активна ли вкладка аналитики
            self._refresh_analytics()  # Обновляем графики

    # Метод загрузки и отображения графиков из папки plots
    def _refresh_analytics(self):
        for w in self.analytics_frame.winfo_children(): w.destroy()  # Очищаем старые изображения из контейнера
        self.photo_refs.clear()  # Очищаем список ссылок на изображения
        plots_dir = "plots"  # Задаём путь к папке с графиками
        if not os.path.exists(plots_dir):  # Проверяем наличие папки
            ttk.Label(self.analytics_frame, text="Папка 'plots' не найдена. Запустите обучение моделей.").pack(pady=50)  # Выводим подсказку
            return  # Прерываем обновление
        png_files = [f for f in os.listdir(plots_dir) if f.endswith(".png")]  # Фильтруем только PNG-файлы
        if not png_files:  # Проверяем наличие файлов
            ttk.Label(self.analytics_frame, text="Графики не найдены.").pack(pady=50)  # Выводим сообщение
            return  # Прерываем
        for png in sorted(png_files):  # Перебираем отсортированные имена файлов
            full_path = os.path.join(plots_dir, png)  # Формируем путь
            try:  # Пытаемся загрузить и отобразить
                img = Image.open(full_path)  # Открываем изображение
                img.thumbnail((800, 600))  # Уменьшаем до максимальных размеров для GUI
                photo = ImageTk.PhotoImage(img)  # Конвертируем в формат Tkinter
                self.photo_refs.append(photo)  # Сохраняем ссылку от сборщика мусора
                lbl = ttk.Label(self.analytics_frame, image=photo)  # Создаём лейбл с изображением
                lbl.pack(pady=10)  # Упаковываем лейбл с отступом
                title = ttk.Label(self.analytics_frame, text=png, font=("Arial", 9))  # Создаём подпись с именем файла
                title.pack(pady=(0, 20))  # Упаковываем подпись
            except Exception as e:  # Ловим ошибки загрузки изображений
                ttk.Label(self.analytics_frame, text=f"Ошибка загрузки {png}: {e}").pack()  # Выводим ошибку
                continue  # Переходим к следующему файлу

if __name__ == "__main__":  # Гарантируем выполнение только при прямом запуске скрипта
    PEAnalyzerGUI()  # Создаём и запускаем экземпляр графического интерфейса