import os
import json
import requests
from datetime import datetime, timedelta
from typing import Dict, List, Tuple

# 3rd party libraries:
# - requests
# - python-dotenv (for loading environment variables)

# Load environment variables
from dotenv import load_dotenv
load_dotenv()

# Weather API keys
OPENWEATHERMAP_API_KEY = os.getenv("OPENWEATHERMAP_API_KEY")
WEATHERAPI_API_KEY = os.getenv("WEATHERAPI_API_KEY")

# API endpoint URLs
OPENWEATHERMAP_ENDPOINT = "http://api.openweathermap.org/data/2.5/weather"
WEATHERAPI_ENDPOINT = "http://api.weatherapi.com/v1/current.json"

# Weather data structure
WeatherData = Dict[str, float]

def get_openweathermap_data(city: str) -> WeatherData:
    """
    Fetch weather data from OpenWeatherMap API.
    
    Args:
        city (str): The city name.
    
    Returns:
        WeatherData: A dictionary containing the weather data.
    """
    params = {
        "q": city,
        "appid": OPENWEATHERMAP_API_KEY,
        "units": "metric"
    }
    response = requests.get(OPENWEATHERMAP_ENDPOINT, params=params)
    response.raise_for_status()
    data = response.json()
    return {
        "temperature": data["main"]["temp"],
        "humidity": data["main"]["humidity"],
        "wind_speed": data["wind"]["speed"],
        "description": data["weather"][0]["description"]
    }

def get_weatherapi_data(city: str) -> WeatherData:
    """
    Fetch weather data from WeatherAPI.
    
    Args:
        city (str): The city name.
    
    Returns:
        WeatherData: A dictionary containing the weather data.
    """
    params = {
        "key": WEATHERAPI_API_KEY,
        "q": city,
        "aqi": "no"
    }
    response = requests.get(WEATHERAPI_ENDPOINT, params=params)
    response.raise_for_status()
    data = response.json()
    return {
        "temperature": data["current"]["temp_c"],
        "humidity": data["current"]["humidity"],
        "wind_speed": data["current"]["wind_kph"],
        "description": data["current"]["condition"]["text"]
    }

def aggregate_weather_data(city: str) -> WeatherData:
    """
    Aggregate weather data from multiple sources.
    
    Args:
        city (str): The city name.
    
    Returns:
        WeatherData: A dictionary containing the aggregated weather data.
    """
    openweathermap_data = get_openweathermap_data(city)
    weatherapi_data = get_weatherapi_data(city)
    
    aggregated_data = {
        "temperature": (openweathermap_data["temperature"] + weatherapi_data["temperature"]) / 2,
        "humidity": (openweathermap_data["humidity"] + weatherapi_data["humidity"]) / 2,
        "wind_speed": (openweathermap_data["wind_speed"] + weatherapi_data["wind_speed"]) / 2,
        "description": f"{openweathermap_data['description']} / {weatherapi_data['description']}"
    }
    
    return aggregated_data

def get_forecast(city: str, days: int = 1) -> List[WeatherData]:
    """
    Get a weather forecast for the specified city and number of days.
    
    Args:
        city (str): The city name.
        days (int, optional): The number of days to forecast. Defaults to 1.
    
    Returns:
        List[WeatherData]: A list of weather data dictionaries for the forecast.
    """
    forecast = []
    for day in range(days):
        date = datetime.now() + timedelta(days=day)
        weather_data = aggregate_weather_data(city)
        weather_data["date"] = date.strftime("%Y-%m-%d")
        forecast.append(weather_data)
    return forecast

def lambda_handler(event: Dict[str, str], context):
    """
    AWS Lambda function handler for the weather API aggregator.
    
    Args:
        event (Dict[str, str]): The event data passed to the Lambda function.
        context (Any): The context object provided by AWS Lambda.
    
    Returns:
        Dict[str, Any]: The response data to be returned by the Lambda function.
    """
    city = event.get("city", "New York")
    days = int(event.get("days", "1"))
    
    try:
        forecast = get_forecast(city, days)
        return {
            "statusCode": 200,
            "body": json.dumps(forecast)
        }
    except Exception as e:
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }

if __name__ == "__main__":
    event = {"city": "London", "days": "3"}
    print(json.dumps(lambda_handler(event, None), indent=2))