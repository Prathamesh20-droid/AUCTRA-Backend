from core.database import get_db_connection
import pymysql
conn = get_db_connection()
cursor = conn.cursor(pymysql.cursors.DictCursor)
team_id = 15 # RCB

print("Before deleting team 15:")
cursor.execute("SELECT id, email, team_id FROM users WHERE team_id = %s", (team_id,))
print("USERS:", cursor.fetchall())

# This is what delete_team does:
cursor.execute("DELETE FROM users WHERE team_id = %s", (team_id,))
cursor.execute("DELETE FROM teams WHERE team_id = %s", (team_id,))
conn.commit()

print("After deleting team 15:")
cursor.execute("SELECT id, email, team_id FROM users")
print("USERS:", cursor.fetchall())

cursor.execute("SELECT team_id, name FROM teams")
print("TEAMS:", cursor.fetchall())
cursor.close()
conn.close()
