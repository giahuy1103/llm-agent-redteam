import json
import logging
from pathlib import Path
import sys

# Ensure we can import from src
sys.path.append(str(Path(__file__).parent.parent))

from src.attack_generator import AttackCorpusGenerator
from src.logging_setup import setup_logging

def main():
    setup_logging("INFO")
    logger = logging.getLogger("generate_corpus")
    
    # Resolve the data directory safely
    base_dir = Path(__file__).resolve().parent.parent
    data_dir = base_dir / "data"
    data_dir.mkdir(exist_ok=True)
    
    output_file = data_dir / "attack_corpus.jsonl"
    
    logger.info("Initializing Attack Corpus Generator...")
    generator = AttackCorpusGenerator()
    test_cases = generator.generate_all()
    
    logger.info(f"Generated {len(test_cases)} adversarial test cases.")
    logger.info(f"Writing corpus to {output_file}...")
    
    # Idempotent write (overwrite if exists)
    with open(output_file, "w", encoding="utf-8") as f:
        for tc in test_cases:
            json_line = json.dumps(tc.to_dict(), ensure_ascii=False)
            f.write(json_line + "\n")
            
    logger.info("[SUCCESS] Attack corpus generated successfully.")

if __name__ == "__main__":
    main()