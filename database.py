
import sqlite3

from datetime import datetime

# =====================================
# DATABASE CONNECTION
# =====================================

conn = sqlite3.connect(
    "job_scam_results.db",
    check_same_thread=False
)

cursor = conn.cursor()

# =====================================
# RESULTS TABLE
# =====================================

cursor.execute("""

CREATE TABLE IF NOT EXISTS results (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    text TEXT,

    ml_score REAL,

    risk_score REAL,

    result TEXT,

    timestamp TEXT

)

""")

# =====================================
# FEEDBACK TABLE
# =====================================

cursor.execute("""

CREATE TABLE IF NOT EXISTS feedback (

    id INTEGER PRIMARY KEY AUTOINCREMENT,

    feedback TEXT,

    timestamp TEXT

)

""")

conn.commit()

# =====================================
# SAVE RESULT
# =====================================

def save_result(

    text,

    ml_score,

    risk_score,

    result

):

    timestamp = datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )

    cursor.execute(

        """

        INSERT INTO results (

            text,

            ml_score,

            risk_score,

            result,

            timestamp

        )

        VALUES (?, ?, ?, ?, ?)

        """,

        (

            text,

            ml_score,

            risk_score,

            result,

            timestamp

        )

    )

    conn.commit()

# =====================================
# SAVE FEEDBACK
# =====================================

def save_feedback(feedback):

    timestamp = datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )

    cursor.execute(

        """

        INSERT INTO feedback (

            feedback,

            timestamp

        )

        VALUES (?, ?)

        """,

        (

            feedback,

            timestamp

        )

    )

    conn.commit()

# =====================================
# GET RESULTS
# =====================================

def get_results():

    cursor.execute(

        """

        SELECT *

        FROM results

        ORDER BY id DESC

        """

    )

    return cursor.fetchall()

# =====================================
# GET FEEDBACKS
# =====================================

def get_feedbacks():

    cursor.execute(

        """

        SELECT *

        FROM feedback

        ORDER BY id DESC

        """

    )

    return cursor.fetchall()
    

