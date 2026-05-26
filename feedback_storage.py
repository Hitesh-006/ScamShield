import sqlite3
import pandas as pd
import os


from datetime import datetime

# =====================================
# DATABASE CONNECTION
# =====================================


conn = sqlite3.connect(
    "user_feedback.db",
    check_same_thread=False
)

cursor = conn.cursor()

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
# SAVE FEEDBACK
# =====================================

def save_feedback(feedback):

    # =================================
    # CURRENT TIME
    # =================================

    timestamp = datetime.now().strftime(
        "%d-%m-%Y %H:%M:%S"
    )

    # =================================
    # SAVE TO SQLITE
    # =================================

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

    # =================================
    # SAVE TO CSV
    # =================================

    save_feedback_csv(
        feedback,
        timestamp
    )

# =====================================
# SAVE CSV FUNCTION
# =====================================

def save_feedback_csv(

    feedback,

    timestamp

):

    try:

        row = {

            "feedback": feedback,

            "timestamp": timestamp

        }

        file_name = "feedback_storage.csv"

        # =============================
        # APPEND EXISTING FILE
        # =============================

        if os.path.exists(file_name):

            old_df = pd.read_csv(file_name)

            new_df = pd.concat(
                [old_df, pd.DataFrame([row])],
                ignore_index=True
            )

        # =============================
        # CREATE NEW FILE
        # =============================

        else:

            new_df = pd.DataFrame([row])

        # =============================
        # SAVE CSV
        # =============================

        new_df.to_csv(
            file_name,
            index=False
        )

    except Exception as e:

        print("CSV FEEDBACK ERROR:", e)

# =====================================
# GET FEEDBACK
# =====================================

def get_feedback():

    cursor.execute(

        """

        SELECT *

        FROM feedback

        ORDER BY id DESC

        """

    )

    return cursor.fetchall()
