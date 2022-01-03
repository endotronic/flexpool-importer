import argparse
from collections import defaultdict
from datetime import datetime, timedelta
from enum import Enum
from functools import partial
import logging
from logging import Logger
from os import getenv, path
import signal
from threading import Event, Lock
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple, Union
from urllib.parse import urlencode, urljoin

import attr
from prometheus_client import start_http_server  # type: ignore
from prometheus_client.core import GaugeMetricFamily, REGISTRY  # type: ignore
from requests_cache import CachedSession


class ConfigurationError(Exception):
    pass


class FlexpoolApiError(Exception):
    pass


class FlexpoolCollector:
    def __init__(
        self,
        base_url: str,
        address: str,
        coin: str,
        query_interval: int,
        logger: Logger,
    ) -> None:
        self.base_url = base_url
        self.address = address
        self.coin = coin

        self.logger = logger
        self.session = CachedSession(expire_after=query_interval)
        REGISTRY.register(self)

        params_dict = dict(coin=coin, address=address)
        self.balance_url = urljoin(base_url, "miner/balance?" + urlencode(params_dict))
        self.stats_url = urljoin(base_url, "miner/stats?" + urlencode(params_dict))

    def describe(self) -> Iterable[GaugeMetricFamily]:
        return []

    def collect(self) -> Iterable[GaugeMetricFamily]:
        try:
            for gauge in self.get_balance_gauges():
                yield gauge

            for gauge in self.get_stats_gauges():
                yield gauge
        except Exception:
            self.logger.error("Could not query Flexpool")

    def get_balance_gauges(self) -> Iterable[GaugeMetricFamily]:
        response = self.session.get(self.balance_url)
        data = response.json()
        error = data.get("error")
        if error:
            raise FlexpoolApiError(error)
        result = data["result"]

        gauge = GaugeMetricFamily(
            "flexpool_balance",
            "flexpool_balance",
            labels=["coin", "address"],
        )
        gauge.add_metric([self.coin, self.address], result["balance"])
        yield gauge

        gauge = GaugeMetricFamily(
            "flexpool_adjusted_balance",
            "Adjusted balance (balanceCountervalue)",
            labels=["coin", "address"],
        )
        gauge.add_metric([self.coin, self.address], result["balanceCountervalue"])
        yield gauge

        gauge = GaugeMetricFamily(
            "flexpool_coin_price",
            "Coin price used to produce adjusted balance",
            labels=["coin", "address"],
        )
        gauge.add_metric([self.coin, self.address], result["price"])
        yield gauge

    def get_stats_gauges(self) -> Iterable[GaugeMetricFamily]:
        response = self.session.get(self.stats_url)
        data = response.json()
        error = data.get("error")
        if error:
            raise FlexpoolApiError(error)
        result = data["result"]

        gauge = GaugeMetricFamily(
            "flexpool_average_effective_hashrate",
            "Average effective hashrate over sime time window (produced by Flexpool)",
            labels=["coin", "address"],
        )
        gauge.add_metric([self.coin, self.address], result["averageEffectiveHashrate"])
        yield gauge

        gauge = GaugeMetricFamily(
            "flexpool_current_effective_hashrate",
            "Current effective hashrate",
            labels=["coin", "address"],
        )
        gauge.add_metric([self.coin, self.address], result["currentEffectiveHashrate"])
        yield gauge

        gauge = GaugeMetricFamily(
            "flexpool_invalid_shares",
            "Invalid shares",
            labels=["coin", "address"],
        )
        gauge.add_metric([self.coin, self.address], result["invalidShares"])
        yield gauge

        gauge = GaugeMetricFamily(
            "flexpool_reported_hashrate",
            "Current hashrate reported by miner",
            labels=["coin", "address"],
        )
        gauge.add_metric([self.coin, self.address], result["reportedHashrate"])
        yield gauge

        gauge = GaugeMetricFamily(
            "flexpool_stale_shares",
            "Stale shares",
            labels=["coin", "address"],
        )
        gauge.add_metric([self.coin, self.address], result["staleShares"])
        yield gauge

        gauge = GaugeMetricFamily(
            "flexpool_valid_shares",
            "Valid shares",
            labels=["coin", "address"],
        )
        gauge.add_metric([self.coin, self.address], result["validShares"])
        yield gauge

    def start(self) -> None:
        start_http_server(8000)
        self.logger.info("Server is running.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Runs a webserver for Prometheus scraping and proxies requests to the Flexpool API."
    )
    parser.add_argument("-c", "--coin", help="coin (default ETH)", default="eth")
    parser.add_argument(
        "-a",
        "--address",
        help="wallet address (default is $ADDRESS env var)",
        default=getenv("ADDRESS"),
    )
    parser.add_argument(
        "-i",
        "--query_interval",
        help="minimum interval for queries (in seconds, default=30)",
        default=30,
    )
    parser.add_argument(
        "--base_url",
        help="base URL override",
        default="https://api.flexpool.io/v2/",
    )
    parser.add_argument("--log_level", default="INFO")
    parser.add_argument("--global_log_level", default="INFO")
    args = parser.parse_args()

    if not args.address:
        raise ConfigurationError(
            "Address not specified on command line or env variable"
        )

    log_level = logging.getLevelName(args.log_level)
    global_log_level = logging.getLevelName(args.global_log_level)
    logging.basicConfig(format="[%(levelname)s]: %(message)s", level=global_log_level)
    logger = logging.getLogger("flexpool_importer")
    logger.setLevel(log_level)

    exit_event = Event()
    signal.signal(signal.SIGINT, lambda _s, _f: exit_event.set())
    signal.signal(signal.SIGHUP, lambda _s, _f: exit_event.set())

    collector = FlexpoolCollector(
        base_url=args.base_url,
        address=args.address,
        coin=args.coin,
        query_interval=args.query_interval,
        logger=logger,
    )
    collector.start()
    exit_event.wait()
