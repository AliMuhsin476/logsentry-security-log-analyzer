from pathlib import Path


def read_log_file(file_path):
    try:
        with open(file_path, "r", encoding="utf-8") as log_file:
            log_lines = log_file.readlines()
            return log_lines

    except FileNotFoundError:
        print("Hata: Log dosyası bulunamadı.")
        return []



project_folder = Path(__file__).resolve().parent.parent
sample_file = project_folder / "sample_logs" / "sample_auth.txt"

log_records = read_log_file(sample_file)

print(f"Okunan toplam log sayısı: {len(log_records)}")
