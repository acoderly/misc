import os
import logging.handlers
import logging.handlers

try:
    import idc
    import idaapi
    import idautils
except ModuleNotFoundError as e:
    pass

log_path = os.getcwd()


def create_logger():
    log_file = os.path.join(log_path, "log.txt")
    handler = logging.handlers.RotatingFileHandler(log_file, maxBytes=1024 * 1024, backupCount=10)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger("log")
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger


def processes():
    current_file = idaapi.get_root_filename()
    count = len([_ for _ in idautils.Functions()])
    if count == 6:
        logger.info("{} has only 6 func".format(current_file))
    if count == 0:
        logger.info("{} has only 0 func".format(current_file))


logger = create_logger()
idaapi.autoWait()

processes()

idc.Exit(0)
