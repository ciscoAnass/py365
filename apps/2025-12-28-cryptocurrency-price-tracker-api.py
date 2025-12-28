import abc
import time
import requests
import logging
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any

# --- Configuration Section ---
# This section defines various configuration parameters for the cryptocurrency price tracker.
# It includes API endpoints, supported trading pairs, caching settings, and logging levels.

# 3rd party libraries required:
# - Flask (for the web API framework)
# - requests (for making HTTP requests to external exchange APIs)
# To install: pip install Flask requests

# Configure logging for detailed operational insights.
# Logs will be printed to the console (standard output).
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('CryptoPriceTrackerAPI')
logger.info("Initializing Cryptocurrency Price Tracker API components...")

# Define API endpoints for various cryptocurrency exchanges.
# These URLs are used to fetch public ticker data.
# The '{symbol}' placeholder will be replaced with the exchange-specific trading pair.
EXCHANGE_API_URLS: Dict[str, str] = {
    'coinbase': 'https://api.pro.coinbase.com/products/{symbol}/ticker',
    'binance': 'https://api.binance.com/api/v3/ticker/price?symbol={symbol}',
    # To extend the API, uncomment and add more exchange endpoints here.
    # Make sure to also implement a corresponding client class and add it to SYMBOL_MAPPING.
    # 'kraken': 'https://api.kraken.com/0/public/Ticker?pair={symbol}',
    # 'gemini': 'https://api.gemini.com/v2/ticker/{symbol}',
}

# A comprehensive list of supported canonical trading pairs.
# This list is used for input validation and to ensure only recognized pairs are processed.
SUPPORTED_PAIRS: List[str] = [
    'BTC-USD', 'ETH-USD', 'XRP-USD', 'LTC-USD', 'ADA-USD', 'SOL-USD', 'DOGE-USD', 'SHIB-USD',
    'BTC-EUR', 'ETH-EUR', 'XRP-EUR', 'LTC-EUR', 'ADA-EUR',
    'BTCUSDT', 'ETHUSDT', 'XRPUSDT', 'LTCUSDT', 'ADAUSDT', 'SOLUSDT', 'DOGEUSDT', 'SHIBUSDT', # Binance specific format
    'BTCEUR', 'ETHEUR', 'XRPEUR', # Binance specific format for EUR pairs
]

# Mapping for symbol normalization across different exchanges.
# Different exchanges often use distinct symbol formats (e.g., 'BTC-USD' on Coinbase vs. 'BTCUSDT' on Binance).
# This dictionary maps a canonical symbol (e.g., 'BTC-USD') to its corresponding format for each exchange.
SYMBOL_MAPPING: Dict[str, Dict[str, str]] = {
    'BTC-USD': {'coinbase': 'BTC-USD', 'binance': 'BTCUSDT'},
    'ETH-USD': {'coinbase': 'ETH-USD', 'binance': 'ETHUSDT'},
    'XRP-USD': {'coinbase': 'XRP-USD', 'binance': 'XRPUSDT'},
    'LTC-USD': {'coinbase': 'LTC-USD', 'binance': 'LTCUSDT'},
    'ADA-USD': {'coinbase': 'ADA-USD', 'binance': 'ADAUSDT'},
    'SOL-USD': {'coinbase': 'SOL-USD', 'binance': 'SOLUSDT'},
    'DOGE-USD': {'coinbase': 'DOGE-USD', 'binance': 'DOGEUSDT'},
    'SHIB-USD': {'coinbase': 'SHIB-USD', 'binance': 'SHIBUSDT'},

    'BTC-EUR': {'coinbase': 'BTC-EUR', 'binance': 'BTCEUR'},
    'ETH-EUR': {'coinbase': 'ETH-EUR', 'binance': 'ETHEUR'},
    'XRP-EUR': {'coinbase': 'XRP-EUR', 'binance': 'XRPEUR'},
    'LTC-EUR': {'coinbase': 'LTC-EUR', 'binance': 'LTCEUR'}, # Assuming LTCEUR on Binance
    'ADA-EUR': {'coinbase': 'ADA-EUR', 'binance': 'ADAEUR'}, # Assuming ADAEUR on Binance

    # Direct mappings for symbols that are already in exchange-specific formats, for completeness
    'BTCUSDT': {'coinbase': 'BTC-USD', 'binance': 'BTCUSDT'}, # Map to canonical if possible
    'ETHUSDT': {'coinbase': 'ETH-USD', 'binance': 'ETHUSDT'},
    'XRPUSDT': {'coinbase': 'XRP-USD', 'binance': 'XRPUSDT'},
    'LTCUSDT': {'coinbase': 'LTC-USD', 'binance': 'LTCUSDT'},
    'ADAUSDT': {'coinbase': 'ADA-USD', 'binance': 'ADAUSDT'},
    'SOLUSDT': {'coinbase': 'SOL-USD', 'binance': 'SOLUSDT'},
    'DOGEUSDT': {'coinbase': 'DOGE-USD', 'binance': 'DOGEUSDT'},
    'SHIBUSDT': {'coinbase': 'SHIB-USD', 'binance': 'SHIBUSDT'},

    'BTCEUR': {'coinbase': 'BTC-EUR', 'binance': 'BTCEUR'},
    'ETHEUR': {'coinbase': 'ETH-EUR', 'binance': 'ETHEUR'},
    'XRPEUR': {'coinbase': 'XRP-EUR', 'binance': 'XRPEUR'},
}

# Default list of exchanges to query if not explicitly specified by the API consumer.
# This ensures that all configured and implemented exchanges are considered by default.
DEFAULT_EXCHANGES: List[str] = list(EXCHANGE_API_URLS.keys())

# Cache Time-To-Live (TTL) in seconds.
# Data stored in the cache older than this TTL will be considered stale and will trigger a new fetch
# from the underlying exchanges to ensure data freshness.
CACHE_TTL_SECONDS: int = 30

# API call timeout for external exchange requests in seconds.
# This prevents the API from hanging indefinitely if an exchange API is unresponsive.
API_REQUEST_TIMEOUT_SECONDS: int = 5

# API response messages for clarity and consistency across all endpoints.
# Standardizing messages helps API consumers understand the outcome of their requests.
API_RESPONSE_MESSAGES: Dict[str, str] = {
    'invalid_symbol': 'Invalid trading symbol provided. Please check the list of supported pairs.',
    'no_data_available': 'No price data could be retrieved for the specified symbol from any active exchange.',
    'internal_error': 'An internal server error occurred while processing your request.',
    'success': 'Price data successfully aggregated.',
    'unauthorized': 'Authentication credentials missing or invalid.', # Placeholder for future auth implementation
    'rate_limit_exceeded': 'Too many requests. Please try again later.' # Placeholder for future rate limiting
}

# --- Utility Functions ---

def normalize_symbol(symbol: str, exchange_name: str) -> Optional[str]:
    """
    Normalizes a given canonical trading symbol to an exchange-specific format.
    This function uses the pre-defined SYMBOL_MAPPING to translate symbols.

    Args:
        symbol (str): The canonical trading symbol (e.g., 'BTC-USD').
        exchange_name (str): The name of the exchange (e.g., 'coinbase', 'binance').

    Returns:
        Optional[str]: The normalized symbol suitable for the specific exchange's API,
                       or None if no mapping is found for the given exchange.
    """
    canonical_symbol = symbol.upper()
    exchange_specific_symbol = SYMBOL_MAPPING.get(canonical_symbol, {}).get(exchange_name.lower())
    if not exchange_specific_symbol:
        logger.debug(f"Normalization failed: Symbol '{symbol}' not mapped for exchange '{exchange_name}'.")
    else:
        logger.debug(f"Normalized '{symbol}' for '{exchange_name}' to '{exchange_specific_symbol}'.")
    return exchange_specific_symbol

# --- Caching Mechanism Implementation ---

class PriceCacheManager:
    """
    Manages the caching of cryptocurrency prices to reduce redundant API calls to exchanges
    and improve response times. This custom cache stores aggregated prices, their timestamps,
    and metadata about the sources. It also handles cache staleness based on a configured TTL.
    """
    def __init__(self, ttl_seconds: int = CACHE_TTL_SECONDS):
        """
        Initializes the PriceCacheManager with a specified Time-To-Live for cached entries.

        Args:
            ttl_seconds (int): The Time-To-Live for cached entries in seconds.
                               Entries older than this duration are considered stale.
        """
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._ttl_seconds: int = ttl_seconds
        logger.info(f"PriceCacheManager initialized with TTL: {self._ttl_seconds} seconds.")

    def _is_stale(self, timestamp: datetime) -> bool:
        """
        Determines if a cached data entry is stale by comparing its timestamp with the current time
        and the configured TTL.

        Args:
            timestamp (datetime): The datetime object representing when the cached data was last updated.

        Returns:
            bool: True if the data is stale (older than TTL), False otherwise.
        """
        now = datetime.now()
        is_stale = (now - timestamp) > timedelta(seconds=self._ttl_seconds)
        if is_stale:
            logger.debug(f"Cache entry is stale: now={now.isoformat()}, timestamp={timestamp.isoformat()}, "
                         f"TTL={self._ttl_seconds}s.")
        return is_stale

    def get_cache(self, key: str) -> Optional[Dict[str, Any]]:
        """
        Retrieves a cached entry for a given key (trading symbol).
        If the entry exists and is not stale, it is returned. Stale entries are automatically removed.

        Args:
            key (str): The cache key, typically the canonical trading symbol (e.g., 'BTC-USD').

        Returns:
            Optional[Dict[str, Any]]: The fresh cached data (a dictionary containing 'price',
                                      'timestamp', 'successful_sources', etc.) if available and valid,
                                      otherwise None.
        """
        cached_data = self._cache.get(key)
        if cached_data:
            cache_timestamp = cached_data.get('timestamp')
            if cache_timestamp and isinstance(cache_timestamp, datetime) and not self._is_stale(cache_timestamp):
                logger.debug(f"Cache hit for key '{key}'. Data is fresh.")
                return cached_data
            else:
                logger.debug(f"Cache hit for key '{key}', but data is stale or timestamp is invalid. Removing entry.")
                self._cache.pop(key, None) # Remove stale or invalid entry
        logger.debug(f"Cache miss for key '{key}'.")
        return None

    def set_cache(self, key: str, price: float, timestamp: datetime,
                  successful_sources: List[str], failed_sources: List[str],
                  sources_queried: int) -> None:
        """
        Stores new aggregated price data in the cache. This data includes the price,
        the time it was fetched, and details about the sources.

        Args:
            key (str): The cache key (canonical trading symbol).
            price (float): The aggregated price value.
            timestamp (datetime): The datetime object representing when this price was aggregated.
            successful_sources (List[str]): A list of names of exchanges that successfully provided data.
            failed_sources (List[str]): A list of names of exchanges that failed to provide data.
            sources_queried (int): The total count of exchanges that were attempted to be queried.
        """
        self._cache[key] = {
            'price': price,
            'timestamp': timestamp,
            'successful_sources': successful_sources,
            'failed_sources': failed_sources,
            'sources_queried': sources_queried,
            'cache_hit_time': datetime.now() # Records when this specific cache entry was last updated
        }
        logger.info(f"Cache updated for key '{key}' with price {price:.4f} "
                    f"from {len(successful_sources)} successful sources. Current cache size: {len(self._cache)}.")

    def clear_cache(self, key: Optional[str] = None) -> None:
        """
        Clears a specific entry from the cache or the entire cache if no key is provided.

        Args:
            key (Optional[str]): The specific key to clear. If None, all cache entries are removed.
        """
        if key:
            if key in self._cache:
                self._cache.pop(key)
                logger.info(f"Cleared cache entry for key: {key}")
            else:
                logger.warning(f"Attempted to clear non-existent cache entry for key: {key}")
        else:
            self._cache.clear()
            logger.info("Cleared entire cache.")

    def get_cache_size(self) -> int:
        """
        Returns the current number of entries stored in the cache.

        Returns:
            int: The total count of cached items.
        """
        return len(self._cache)

    def get_all_cached_keys(self) -> List[str]:
        """
        Returns a list of all keys (symbols) currently present in the cache.

        Returns:
            List[str]: A list of cache keys.
        """
        return list(self._cache.keys())

# --- Exchange Client Abstract Base Class ---

class ExchangeClient(abc.ABC):
    """
    Abstract Base Class (ABC) for cryptocurrency exchange clients.
    This class defines the standard interface that all concrete exchange clients must implement.
    It provides common functionality like session management and generic error handling.
    """
    def __init__(self, name: str, api_url_template: str):
        """
        Initializes an ExchangeClient instance.

        Args:
            name (str): The unique name of the exchange (e.g., 'coinbase', 'binance').
            api_url_template (str): The URL template for the exchange's ticker API,
                                    containing a '{symbol}' placeholder.
        """
        self.name = name
        self.api_url_template = api_url_template
        # Use a requests.Session for efficient connection pooling, especially for multiple requests.
        self._session = requests.Session()
        logger.debug(f"Initialized {self.name} ExchangeClient with API URL template: {self.api_url_template}")

    @abc.abstractmethod
    def _fetch_price_from_api(self, symbol: str) -> Optional[float]:
        """
        Abstract method that must be implemented by concrete exchange client classes.
        This method is responsible for making the actual API call to the exchange
        and parsing the response to extract the raw price.

        Args:
            symbol (str): The exchange-specific symbol for the trading pair.

        Returns:
            Optional[float]: The price as a float, or None if fetching or parsing fails.
        """
        raise NotImplementedError("Subclasses must implement _fetch_price_from_api method.")

    def get_price(self, canonical_symbol: str) -> Optional[Dict[str, Any]]:
        """
        Fetches the price for a given canonical symbol from the exchange.
        This method handles symbol normalization, network requests, and general API call error handling.

        Args:
            canonical_symbol (str): The standard trading symbol (e.g., 'BTC-USD').

        Returns:
            Optional[Dict[str, Any]]: A dictionary containing 'price' (float) and 'source' (str)
                                      if the operation is successful, otherwise None.
        """
        # First, normalize the canonical symbol to the format expected by this specific exchange.
        exchange_symbol = normalize_symbol(canonical_symbol, self.name)
        if not exchange_symbol:
            logger.warning(f"Skipping {self.name} for {canonical_symbol}: No mapped symbol found for this exchange.")
            return None

        try:
            logger.debug(f"Attempting to fetch price for {canonical_symbol} as '{exchange_symbol}' from {self.name}.")
            price = self._fetch_price_from_api(exchange_symbol)
            if price is not None:
                logger.info(f"Successfully fetched {canonical_symbol} price from {self.name}: {price:.4f}")
                return {'price': price, 'source': self.name}
            else:
                logger.warning(f"Failed to parse or retrieve price for {canonical_symbol} from {self.name} API. "
                               f"Possibly due to missing data or API change.")
                return None
        except requests.exceptions.Timeout:
            logger.error(f"Timeout (>{API_REQUEST_TIMEOUT_SECONDS}s) fetching {canonical_symbol} from {self.name}.")
            return None
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Connection error fetching {canonical_symbol} from {self.name}: {e}. "
                         f"Check network or exchange API status.")
            return None
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error {e.response.status_code} fetching {canonical_symbol} from {self.name}: {e}.")
            # Specific handling for 404 (Not Found) for a symbol, etc.
            if e.response.status_code == 404:
                logger.warning(f"Symbol '{exchange_symbol}' might not exist on {self.name}.")
            return None
        except (ValueError, TypeError, json.JSONDecodeError) as e:
            logger.error(f"Data parsing error for {canonical_symbol} from {self.name}: {e}. "
                         f"API response might be malformed or unexpected.")
            return None
        except Exception as e:
            logger.critical(f"An unexpected error occurred while fetching {canonical_symbol} from {self.name}: {e}",
                            exc_info=True) # Log full traceback for critical errors
            return None

    def __repr__(self) -> str:
        """
        Provides a developer-friendly string representation for the ExchangeClient object.
        """
        return f"<{self.name.capitalize()}Client>"

# --- Concrete Exchange Client Implementations ---

class CoinbaseClient(ExchangeClient):
    """
    Concrete implementation of ExchangeClient for Coinbase Pro (now Coinbase Advanced Trade API for public data).
    It specifically targets the public ticker endpoint to fetch real-time price data.
    """
    def __init__(self):
        """
        Initializes the CoinbaseClient, setting its name and API URL based on configuration.
        """
        super().__init__('coinbase', EXCHANGE_API_URLS['coinbase'])
        logger.debug("CoinbaseClient instance created.")

    def _fetch_price_from_api(self, symbol: str) -> Optional[float]:
        """
        Fetches the price for a given Coinbase-specific symbol from the Coinbase Pro API.

        Coinbase Pro ticker API example response structure:
        {"trade_id": 12345, "price": "100.00", "size": "1.0", "bid": "99.99", "ask": "100.01", ...}

        Args:
            symbol (str): The Coinbase-specific trading symbol (e.g., 'BTC-USD').

        Returns:
            Optional[float]: The parsed price as a float, or None if the 'price' field is missing or invalid.
        """
        url = self.api_url_template.format(symbol=symbol)
        logger.debug(f"Requesting Coinbase API for {symbol} at: {url}")
        response = self._session.get(url, timeout=API_REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        price_str = data.get('price')
        if price_str:
            return float(price_str)
        else:
            logger.warning(f"Coinbase response for {symbol} did not contain a valid 'price' field: {data}")
            return None

class BinanceClient(ExchangeClient):
    """
    Concrete implementation of ExchangeClient for Binance.
    It fetches price data from Binance's public `/api/v3/ticker/price` endpoint.
    """
    def __init__(self):
        """
        Initializes the BinanceClient, setting its name and API URL based on configuration.
        """
        super().__init__('binance', EXCHANGE_API_URLS['binance'])
        logger.debug("BinanceClient instance created.")

    def _fetch_price_from_api(self, symbol: str) -> Optional[float]:
        """
        Fetches the price for a given Binance-specific symbol from the Binance API.

        Binance ticker API example response structure:
        {"symbol": "BTCUSDT", "price": "100.00"}

        Args:
            symbol (str): The Binance-specific trading symbol (e.g., 'BTCUSDT').

        Returns:
            Optional[float]: The parsed price as a float, or None if the 'price' field is missing or invalid.
        """
        url = self.api_url_template.format(symbol=symbol)
        logger.debug(f"Requesting Binance API for {symbol} at: {url}")
        response = self._session.get(url, timeout=API_REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        price_str = data.get('price')
        if price_str:
            return float(price_str)
        else:
            logger.warning(f"Binance response for {symbol} did not contain a valid 'price' field: {data}")
            return None

# --- Price Aggregation Service ---

class PriceAggregatorService:
    """
    The central service responsible for orchestrating the aggregation of cryptocurrency prices.
    It interacts with multiple exchange clients to fetch data, utilizes a caching mechanism
    to optimize performance, calculates an average price, and handles various error scenarios.
    """
    def __init__(self, cache_manager: PriceCacheManager, exchange_clients: Dict[str, ExchangeClient]):
        """
        Initializes the PriceAggregatorService.

        Args:
            cache_manager (PriceCacheManager): An instance of the cache manager for price caching.
            exchange_clients (Dict[str, ExchangeClient]): A dictionary where keys are exchange names
                                                          (e.g., 'coinbase') and values are
                                                          initialized ExchangeClient instances.
        """
        self.cache_manager = cache_manager
        self.exchange_clients = exchange_clients
        logger.info(f"PriceAggregatorService initialized with {len(self.exchange_clients)} exchange clients: "
                    f"{', '.join(self.exchange_clients.keys())}.")

    def get_aggregated_price(self, symbol: str,
                             active_exchanges: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Aggregates real-time price data for a given symbol from selected exchanges.
        The process involves:
        1. Input validation for the symbol.
        2. Attempting to retrieve a fresh price from the cache.
        3. If cache miss or stale, querying selected exchanges.
        4. Calculating an average from successful responses.
        5. Updating the cache with the new aggregated data.
        6. Returning a detailed result, including source information and status.

        Args:
            symbol (str): The canonical trading symbol (e.g., 'BTC-USD'). Case-insensitive input is handled.
            active_exchanges (Optional[List[str]]): An optional list of specific exchange names (lowercase)
                                                    to query. If None, all configured exchanges are used.

        Returns:
            Dict[str, Any]: A dictionary containing the aggregated price, timestamp,
                            lists of successful/failed sources, and other relevant metadata.
                            The 'status' field indicates 'success' or 'error'.
        """
        canonical_symbol = symbol.upper()

        # Step 1: Validate the canonical_symbol against the list of SUPPORTED_PAIRS.
        # This prevents unnecessary downstream processing for invalid inputs.
        if canonical_symbol not in SUPPORTED_PAIRS:
            logger.warning(f"Requested symbol '{canonical_symbol}' is not supported.")
            return {
                'status': 'error',
                'message': API_RESPONSE_MESSAGES['invalid_symbol'],
                'symbol': canonical_symbol,
                'details': f"Supported pairs include: {', '.join(sorted(SUPPORTED_PAIRS)[:10])}..." # Show top 10
            }

        # Step 2: Attempt to retrieve the price from the cache first.
        # This significantly improves performance and reduces load on external APIs.
        cached_data = self.cache_manager.get_cache(canonical_symbol)
        if cached_data:
            logger.info(f"Returning cached price for {canonical_symbol}: {cached_data['price']:.4f}")
            return {
                'status': 'success',
                'message': API_RESPONSE_MESSAGES['success'],
                'symbol': canonical_symbol,
                'price': round(cached_data['price'], 4), # Ensure consistent rounding for output
                'timestamp': cached_data['timestamp'].isoformat(),
                'source_info': {
                    'total_sources_queried': cached_data['sources_queried'],
                    'successful_sources': cached_data['successful_sources'],
                    'failed_sources': cached_data['failed_sources'],
                    'cache_hit': True,
                    'last_updated_time_utc': cached_data['timestamp'].isoformat()
                }
            }

        # Step 3: If cache is missed or stale, determine which exchanges to query.
        # Filter the requested_exchanges to ensure they are configured and available.
        effective_exchanges_to_query: List[str]
        if active_exchanges:
            effective_exchanges_to_query = [
                ex.lower() for ex in active_exchanges if ex.lower() in self.exchange_clients
            ]
            if not effective_exchanges_to_query:
                logger.warning(f"No valid or configured exchanges found in requested list: {active_exchanges}. "
                               f"Configured: {list(self.exchange_clients.keys())}")
                return {
                    'status': 'error',
                    'message': 'No valid exchanges specified or configured to query.',
                    'symbol': canonical_symbol,
                    'details': f"Available exchanges: {', '.join(self.exchange_clients.keys())}"
                }
        else:
            effective_exchanges_to_query = DEFAULT_EXCHANGES

        # Select only the available and specified exchange clients.
        available_exchange_clients = {
            name: client for name, client in self.exchange_clients.items()
            if name in effective_exchanges_to_query
        }

        if not available_exchange_clients:
            logger.error(f"No configured exchange clients available for querying symbol {canonical_symbol} "
                         f"from the determined list: {effective_exchanges_to_query}.")
            return {
                'status': 'error',
                'message': API_RESPONSE_MESSAGES['no_data_available'],
                'symbol': canonical_symbol,
                'details': "No exchange clients were configured or available to query after filtering."
            }

        logger.info(f"Querying {len(available_exchange_clients)} exchanges for {canonical_symbol}: "
                    f"{', '.join(available_exchange_clients.keys())} (cache miss/stale).")

        # Step 4: Fetch prices from each selected exchange client.
        # This is currently sequential. For high-performance needs, this could be parallelized
        # using `concurrent.futures.ThreadPoolExecutor` or `asyncio`.
        fetched_prices: List[float] = []
        successful_sources: List[str] = []
        failed_sources: List[str] = []
        start_fetch_time = time.monotonic() # Measure the time taken for API calls

        for exchange_name, client in available_exchange_clients.items():
            price_data = client.get_price(canonical_symbol)
            if price_data:
                fetched_prices.append(price_data['price'])
                successful_sources.append(exchange_name)
            else:
                failed_sources.append(exchange_name)

        end_fetch_time = time.monotonic()
        fetch_duration = end_fetch_time - start_fetch_time
        logger.info(f"Completed fetching prices for {canonical_symbol} in {fetch_duration:.2f} seconds. "
                    f"Successful: {len(successful_sources)}, Failed: {len(failed_sources)}.")

        # Step 5: Calculate the average price from successfully retrieved prices.
        # If no prices were fetched successfully, report an error.
        aggregated_price: Optional[float] = None
        current_timestamp = datetime.now()

        if fetched_prices:
            aggregated_price = sum(fetched_prices) / len(fetched_prices)
            logger.info(f"Calculated aggregated price for {canonical_symbol}: {aggregated_price:.4f}")

            # Step 6: Update the cache with the newly aggregated price.
            self.cache_manager.set_cache(
                canonical_symbol,
                aggregated_price,
                current_timestamp,
                successful_sources,
                failed_sources,
                len(available_exchange_clients)
            )
            return {
                'status': 'success',
                'message': API_RESPONSE_MESSAGES['success'],
                'symbol': canonical_symbol,
                'price': round(aggregated_price, 4), # Round to 4 decimal places for consistent output
                'timestamp': current_timestamp.isoformat(),
                'source_info': {
                    'total_sources_queried': len(available_exchange_clients),
                    'successful_sources': successful_sources,
                    'failed_sources': failed_sources,
                    'cache_hit': False,
                    'fetch_duration_seconds': round(fetch_duration, 2),
                    'last_updated_time_utc': current_timestamp.isoformat()
                }
            }
        else:
            logger.warning(f"Could not retrieve price data for {canonical_symbol} from any active exchange "
                           f"after querying {len(available_exchange_clients)} sources.")
            return {
                'status': 'error',
                'message': API_RESPONSE_MESSAGES['no_data_available'],
                'symbol': canonical_symbol,
                'source_info': {
                    'total_sources_queried': len(available_exchange_clients),
                    'successful_sources': successful_sources,
                    'failed_sources': failed_sources,
                    'cache_hit': False,
                    'fetch_duration_seconds': round(fetch_duration, 2),
                    'last_updated_time_utc': current_timestamp.isoformat() # Still provide a timestamp of attempt
                },
                'details': "All attempted exchanges either failed to respond or did not provide valid data for this symbol."
            }

# --- Flask API Implementation ---

# Import Flask related modules after defining core logic for clarity and organization.
from flask import Flask, jsonify, request

app = Flask(__name__)

# Initialize core components of the API:
# 1. PriceCacheManager: Handles caching of aggregated prices.
price_cache_manager = PriceCacheManager(ttl_seconds=CACHE_TTL_SECONDS)

# 2. ExchangeClient instances: One for each supported exchange.
# These clients are responsible for interacting with their respective external APIs.
exchange_clients_instances: Dict[str, ExchangeClient] = {
    'coinbase': CoinbaseClient(),
    'binance': BinanceClient(),
    # Add new exchange client instances here if new ExchangeClient classes are implemented.
    # E.g., 'kraken': KrakenClient(),
    # Ensure the keys here match the exchange names used in EXCHANGE_API_URLS and SYMBOL_MAPPING.
}

# 3. PriceAggregatorService: The main business logic layer that coordinates fetching,
#    aggregation, and caching.
price_aggregator_service = PriceAggregatorService(
    cache_manager=price_cache_manager,
    exchange_clients=exchange_clients_instances
)

logger.info("Flask application initialized and components are ready.")

@app.route('/')
def index() -> Tuple[Any, int]:
    """
    Root endpoint for the API. Provides a basic welcome message, API version, and a list of available endpoints.
    This serves as an entry point for users to understand the API structure.
    """
    logger.info("Accessing root endpoint.")
    return jsonify({
        'api_name': 'Cryptocurrency Price Tracker API',
        'version': '1.0.0',
        'description': 'Aggregates real-time crypto prices from multiple exchanges and provides an average price.',
        'endpoints': {
            '/api/v1/price/<symbol>': {
                'method': 'GET',
                'description': 'Get aggregated price for a specific cryptocurrency symbol.',
                'example': '/api/v1/price/BTC-USD',
                'query_parameters': {
                    'exchanges': 'Optional, comma-separated list of exchange names to query (e.g., coinbase,binance).'
                }
            },
            '/api/v1/health': {
                'method': 'GET',
                'description': 'Check the health status of the API and its components.'
            },
            '/': {
                'method': 'GET',
                'description': 'This welcome message and API overview.'
            }
        },
        'status': 'operational',
        'timestamp': datetime.now().isoformat()
    }), 200

@app.route('/api/v1/health', methods=['GET'])
def health_check() -> Tuple[Any, int]:
    """
    Health check endpoint to verify that the API and its underlying services are functioning correctly.
    It reports on the status of various components like loaded exchange clients and the cache manager.
    """
    logger.info("Accessing health check endpoint.")
    try:
        # Check if exchange clients are initialized and gather their names.
        active_clients = sorted([client.name for client in price_aggregator_service.exchange_clients.values()])
        # Report current cache status.
        cache_size = price_cache_manager.get_cache_size()
        cached_keys = price_cache_manager.get_all_cached_keys()

        health_status = {
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'message': 'API is operational and responsive.',
            'components': {
                'price_aggregator_service': 'running',
                'exchange_clients_loaded': active_clients if active_clients else "None",
                'cache_manager': {
                    'status': 'running',
                    'current_size': cache_size,
                    'ttl_seconds': CACHE_TTL_SECONDS,
                    'cached_symbols_sample': cached_keys[:5] if cached_keys else [] # Show a sample of cached symbols
                }
            },
            'dependencies_status': {
                'requests_library': 'ok',
                'flask_framework': 'ok'
            }
        }
        logger.info("Health check passed.")
        return jsonify(health_status), 200
    except Exception as e:
        logger.exception("Health check failed due to an unexpected error in one of the components.")
        return jsonify({
            'status': 'unhealthy',
            'timestamp': datetime.now().isoformat(),
            'message': f'API encountered a critical error during health check: {str(e)}',
            'details': 'Please review server logs for detailed traceback and error information.'
        }), 500

@app.route('/api/v1/price/<string:symbol>', methods=['GET'])
def get_price_endpoint(symbol: str) -> Tuple[Any, int]:
    """
    Main endpoint to retrieve the aggregated price for a specified cryptocurrency trading symbol.
    It supports an optional query parameter 'exchanges' to filter which exchanges are queried.

    Args:
        symbol (str): The cryptocurrency trading symbol (e.g., 'BTC-USD', 'ETH-EUR').
                      The symbol is case-insensitive for input but will be normalized internally.

    Query Parameters:
        exchanges (str, optional): A comma-separated string of exchange names (e.g., "coinbase,binance").
                                   If this parameter is provided, only these specified exchanges will be
                                   queried. If omitted, the `DEFAULT_EXCHANGES` configuration will be used.

    Returns:
        Tuple[Dict[str, Any], int]: A JSON response containing the aggregated price data
                                    and an appropriate HTTP status code (200 for success,
                                    400 for bad request, 503 for service unavailable, 500 for internal errors).
    """
    logger.info(f"API request received for symbol: '{symbol}'. Query parameters: {request.args}")

    # Process the 'exchanges' query parameter if it is provided by the client.
    # This allows users to customize which exchanges they want data from.
    requested_exchanges_param = request.args.get('exchanges')
    active_exchanges_from_query: Optional[List[str]] = None
    if requested_exchanges_param:
        # Split the string by comma, strip whitespace, and convert to lowercase for consistent processing.
        active_exchanges_from_query = [ex.strip().lower() for ex in requested_exchanges_param.split(',')]
        logger.debug(f"Client requested specific exchanges: {active_exchanges_from_query}")
    
    try:
        # Delegate the actual price aggregation logic to the PriceAggregatorService.
        # This separation of concerns keeps the Flask route handler clean.
        result = price_aggregator_service.get_aggregated_price(symbol, active_exchanges=active_exchanges_from_query)
        
        # Determine the appropriate HTTP status code based on the result from the service.
        if result['status'] == 'success':
            logger.info(f"Successfully responded for '{symbol}': price={result['price']:.4f}, cache_hit={result['source_info']['cache_hit']}.")
            return jsonify(result), 200
        elif result['status'] == 'error' and result['message'] == API_RESPONSE_MESSAGES['invalid_symbol']:
            logger.warning(f"Invalid symbol '{symbol}' requested by client. Returning 400 Bad Request.")
            return jsonify(result), 400 # Bad Request for invalid input symbol
        elif result['status'] == 'error' and result['message'] == API_RESPONSE_MESSAGES['no_data_available']:
            logger.error(f"No price data available for '{symbol}' from any configured exchange. Returning 503 Service Unavailable.")
            return jsonify(result), 503 # Service Unavailable if no data could be retrieved
        else:
            # Catch-all for other types of errors from the aggregation service.
            logger.error(f"Internal error processing request for '{symbol}': {result.get('message', 'Unknown aggregation error')}. Returning 500 Internal Server Error.")
            return jsonify(result), 500 # Internal Server Error for unexpected aggregation issues
    except Exception as e:
        # This block catches any unexpected exceptions that might occur within the route handler
        # or propagate from deeper layers not caught by the service's error handling.
        logger.exception(f"Unhandled exception during price aggregation request for '{symbol}'.")
        return jsonify({
            'status': 'error',
            'message': API_RESPONSE_MESSAGES['internal_error'],
            'symbol': symbol,
            'details': f"An unexpected server error occurred: {str(e)}"
        }), 500

# --- Main Execution Block ---

if __name__ == '__main__':
    # This block allows the Flask application to be run directly using Python.
    # In a production environment, it is recommended to use a production-ready WSGI server
    # such as Gunicorn or uWSGI for better performance, stability, and management.
    logger.info("Starting Cryptocurrency Price Tracker API server.")
    logger.info(f"API will run on host '{'0.0.0.0'}' and port '{5000}'. "
                f"Accessible at http://127.0.0.1:5000 in most local development setups.")
    logger.info("To test, open your browser or use curl:")
    logger.info("  - Welcome: curl http://localhost:5000/")
    logger.info("  - Health Check: curl http://localhost:5000/api/v1/health")
    logger.info("  - BTC-USD Price (all exchanges): curl http://localhost:5000/api/v1/price/BTC-USD")
    logger.info("  - ETH-USD Price (specific exchanges): curl \"http://localhost:5000/api/v1/price/ETH-USD?exchanges=coinbase\"")
    
    try:
        # `debug=False` for production-like behavior, `host='0.0.0.0'` makes it accessible externally.
        app.run(debug=False, host='0.0.0.0', port=5000)
    except Exception as e:
        logger.critical(f"Failed to start Flask application due to a critical error: {e}", exc_info=True)
        # In a real-world scenario, you might want to send alerts or perform more robust cleanup here.
```