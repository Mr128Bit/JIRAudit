from enum import Enum

class Color(Enum):
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    GREY = "\033[97m"
    PURPLE = "\033[95m"
    ENDFORMAT = "\033[00m"

    def format(string, color):
        return f"{color.value}{string}{Color.ENDFORMAT.value}"
