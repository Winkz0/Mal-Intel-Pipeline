import sqlite3
import datetime
from pathlib import Path

# Adjust path as necessary to sit at the root of your pipeline
DB_PATH = Path(__file__).parent.parent.parent / "pipeline.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS samples (
            sha256 TEXT PRIMARY KEY,
            family TEXT,
            status TEXT,
            acquired_at TIMESTAMP,
            analyzed_at TIMESTAMP,
            synthesized_at TIMESTAMP,
            reported_at TIMESTAMP
        )
    ''')
    try:
        cursor.execute("ALTER TABLE samples ADD COLUMN triage_score INTEGER DEFAULT 0")
        cursor.execute("ALTER TABLE samples ADD COLUMN needs_dynamic BOOLEAN DEFAULT 0")
    except sqlite3.OperationalError:
        pass # Columns already exist
    conn.commit()
    conn.close()

def update_status(sha256: str, status: str, family: str = "Unknown"):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    now = datetime.datetime.now().isoformat()
    
    if status == 'ACQUIRED':
        cursor.execute('''
            INSERT OR REPLACE INTO samples (sha256, family, status, acquired_at)
            VALUES (?, ?, ?, ?)
        ''', (sha256, family, status, now))
    else:
        # Dynamically update the timestamp column based on status
        time_col = f"{status.lower()}_at"
        cursor.execute(f'''
            UPDATE samples SET status = ?, {time_col} = ? WHERE sha256 = ?
        ''', (status, now, sha256))
        
    conn.commit()
    conn.close()

def get_samples_by_status(status: str) -> list[str]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT sha256 FROM samples WHERE status = ?', (status,))
    results = [row[0] for row in cursor.fetchall()]
    conn.close()
    return results

# NEW: Update scoring function
def update_triage_score(sha256: str, score: int, needs_dynamic: bool):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE samples SET triage_score = ?, needs_dynamic = ? WHERE sha256 = ?
    ''', (score, int(needs_dynamic), sha256))
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("[+] Pipeline state database initialized.")