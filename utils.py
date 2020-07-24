from datetime import datetime as dt
import os

database_dt_format = "%Y-%m-%d %H:%M:%S.%f"  # datetime string format, json do not support datetime objects
execution_log_filename = "execution_log.txt"  # execution logfile
execution_log_path = os.path.join(os.curdir, execution_log_filename)  # execution logfile path


def init_execution_log():
    with open(execution_log_path, "w") as f:
        f.write(str(dt.utcnow().strftime(database_dt_format) + "\n"))


def update_execution_log(data):
    with open(execution_log_path, "a") as f:
        f.write(str(dt.utcnow().strftime(database_dt_format)) + ": " + str(data) + "\n")
