from pathlib import Path
import sys

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from main import app, db, test_database_connection


def main():
    test_database_connection()
    with app.app_context():
        db.drop_all()
        db.create_all()
    print("Database schema reset successfully.")


if __name__ == "__main__":
    main()
