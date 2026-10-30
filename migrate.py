import os
import psycopg2
from config import Config
from urllib.parse import urlparse

def run_migration():
    print("Starting database schema migration...")
    db_url = Config.SQLALCHEMY_DATABASE_URI
    if "+psycopg2" in db_url:
        db_url = db_url.replace("+psycopg2", "")
    
    parsed = urlparse(db_url)
    conn = psycopg2.connect(
        dbname=parsed.path.lstrip("/"),
        user=parsed.username,
        password=parsed.password,
        host=parsed.hostname or "localhost",
        port=parsed.port or 5432
    )
    conn.autocommit = True
    cur = conn.cursor()

    migration_file = os.path.join(
        os.path.dirname(__file__),
        "migrations",
        "001_complete_forensics_schema.sql"
    )

    with open(migration_file, "r") as f:
        sql = f.read()

    print(f"Applying migration from {migration_file}...")
    cur.execute(sql)
    print("Migration applied successfully!")

    # Verify all 12 tables exist
    cur.execute("""
        SELECT table_name 
        FROM information_schema.tables 
        WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
        ORDER BY table_name;
    """)
    tables = [row[0] for row in cur.fetchall()]
    print(f"Found {len(tables)} base tables in database: {', '.join(tables)}")

    # Verify views
    cur.execute("""
        SELECT table_name 
        FROM information_schema.views 
        WHERE table_schema = 'public'
        ORDER BY table_name;
    """)
    views = [row[0] for row in cur.fetchall()]
    print(f"Found {len(views)} analytical views in database: {', '.join(views)}")

    cur.close()
    conn.close()

if __name__ == "__main__":
    run_migration()
