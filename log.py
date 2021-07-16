import logging

LOG_DIR = "./logs"
loggers = ["manager", "client", "server", "node"]
STD_LOG_LEVEL = logging.DEBUG
FILE_LOG_LEVEL = logging.INFO


class LoggerFormatter(logging.Formatter):
    name_just = 20
    level_just = 15

    def format(self, record):
        time = self.formatTime(record, self.datefmt)
        return (
            f"===[{time}]===[{record.name}]".ljust(self.name_just, "=")
            + f"===[{record.levelname}]===".ljust(self.level_just, "=")
            + f" {record.getMessage()} :: ({record.filename}:{record.lineno})"
        )


default_format = LoggerFormatter()


def init():
    # setting logger
    stdout_h = logging.StreamHandler()
    filelg_h = logging.FileHandler(f"{LOG_DIR}/network.log")
    stdout_h.setLevel(STD_LOG_LEVEL)
    filelg_h.setLevel(FILE_LOG_LEVEL)
    stdout_h.setFormatter(default_format)
    filelg_h.setFormatter(default_format)

    for logger_name in loggers:
        logger = logging.getLogger(logger_name)
        logger.setLevel(STD_LOG_LEVEL)
        logger.addHandler(stdout_h)
        logger.addHandler(filelg_h)
