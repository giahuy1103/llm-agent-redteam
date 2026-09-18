"""Configuration management for the LLM Agent Red-Teaming Framework.

Loads configuration from environment variables and `.env` files, resolves paths
consistently using `pathlib.Path` relative to the project root, and validates
critical security evaluation prerequisites.
"""

from dataclasses import dataclass
import os
from pathlib import Path
from dotenv import load_dotenv

from src.exceptions import ConfigError


@dataclass(frozen=True)
class Config:
    """Immutable runtime configuration container.

    Attributes:
        base_dir: Absolute root directory of the project.
        gemini_api_key: Secret API key for Google GenAI / Gemini API.
        gemini_model: Target model identifier (default: 'gemini-2.5-flash-lite').
        db_path: Absolute path to the mock SQLite database file.
        mock_files_dir: Absolute path to the directory containing mock files.
        logs_dir: Absolute path to the log storage directory.
        results_dir: Absolute path to the evaluation and audit results directory.
        log_level: Root logging level ('DEBUG', 'INFO', 'WARNING', 'ERROR').
    """

    base_dir: Path
    gemini_api_key: str
    gemini_model: str
    db_path: Path
    mock_files_dir: Path
    logs_dir: Path
    results_dir: Path
    log_level: str

    def validate(self) -> None:
        """Validates that all mandatory configuration parameters are present.

        Raises:
            ConfigError: If GEMINI_API_KEY is missing or blank.
        """
        if not self.gemini_api_key or not self.gemini_api_key.strip():
            raise ConfigError(
                "Missing required environment variable: GEMINI_API_KEY. "
                "Please configure it in your .env file or environment before running."
            )

    def ensure_directories(self) -> None:
        """Ensures that required runtime directories exist on the filesystem."""
        self.mock_files_dir.mkdir(parents=True, exist_ok=True)
        self.logs_dir.mkdir(parents=True, exist_ok=True)
        self.results_dir.mkdir(parents=True, exist_ok=True)


def load_config(env_file: Path | str | None = None) -> Config:
    """Loads and instantiates application configuration.

    Args:
        env_file: Optional path to a specific .env file. If omitted, checks
            the project root directory for `.env`.

    Returns:
        Config: Populated configuration dataclass.
    """
    # Resolve project root relative to this config file (llm-agent-redteam/)
    base_dir = Path(__file__).resolve().parent.parent

    if env_file:
        load_dotenv(dotenv_path=env_file)
    else:
        default_env = base_dir / ".env"
        if default_env.exists():
            load_dotenv(dotenv_path=default_env)
        else:
            # Fallback to current working directory or environment
            load_dotenv()

    gemini_api_key = os.getenv("GEMINI_API_KEY", "").strip()
    gemini_model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash-lite").strip()
    log_level = os.getenv("LOG_LEVEL", "INFO").strip().upper()

    db_path = base_dir / "data" / "mock.db"
    mock_files_dir = base_dir / "data" / "mock_files"
    logs_dir = base_dir / "logs"
    results_dir = base_dir / "results"

    config = Config(
        base_dir=base_dir,
        gemini_api_key=gemini_api_key,
        gemini_model=gemini_model,
        db_path=db_path,
        mock_files_dir=mock_files_dir,
        logs_dir=logs_dir,
        results_dir=results_dir,
        log_level=log_level,
    )
    config.ensure_directories()
    return config
