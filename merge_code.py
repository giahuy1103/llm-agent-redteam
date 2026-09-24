import os
from pathlib import Path

def merge_project_code():
    output_file = "all_code_context.txt"
    # Chỉ đọc những thư mục chứa code thật, bỏ qua .venv, logs, db
    target_dirs = ["src", "scripts", "tests"] 
    
    with open(output_file, "w", encoding="utf-8") as outfile:
        for d in target_dirs:
            if not os.path.exists(d): continue
            for root, _, files in os.walk(d):
                for file in files:
                    if file.endswith(".py"):
                        filepath = Path(root) / file
                        outfile.write(f"\n{'='*60}\n")
                        outfile.write(f"FILE: {filepath.as_posix()}\n")
                        outfile.write(f"{'='*60}\n\n")
                        with open(filepath, "r", encoding="utf-8") as infile:
                            outfile.write(infile.read() + "\n")
                            
    print(f"[SUCCESS] Toàn bộ code đã được gộp vào file: {output_file}")

if __name__ == "__main__":
    merge_project_code()