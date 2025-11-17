from fuzzer.runners.juice_shop import run_juice_shop
from fuzzer.runners.dvwa import run_dvwa
from fuzzer.runners.bwapp import run_bwapp
from fuzzer.runners.storage import parse_proxy_log

RUNNERS = {
    "juice-shop": run_juice_shop,
    "dvwa": run_dvwa,
    "bwapp": run_bwapp,
}

__all__ = [
    "RUNNERS",
    "parse_proxy_log",
    "run_juice_shop",
    "run_dvwa",
    "run_bwapp",
]
