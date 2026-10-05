from core.database import get_db_connection
import pymysql
conn = get_db_connection()
cursor = conn.cursor(pymysql.cursors.DictCursor)
cursor.execute("SELECT id, email, team_id FROM users")
print("USERS:", cursor.fetchall())
cursor.execute("SELECT team_id, name FROM teams")
print("TEAMS:", cursor.fetchall())
cursor.close()
conn.close()
