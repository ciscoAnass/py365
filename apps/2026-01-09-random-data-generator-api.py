# random-data-generator-api.py

# This script implements a FastAPI application that serves as an API wrapper
# for the 'Faker' library. It provides various endpoints to generate
# diverse types of fake data suitable for testing, development, and
# populating databases.
#
# To run this application:
# 1. Ensure you have Python 3.7+ installed.
# 2. Install the necessary libraries:
#    pip install fastapi uvicorn faker pydantic
# 3. Save this code as `main.py` (or any other name).
# 4. Run the application using Uvicorn:
#    uvicorn main:app --reload --port 8000
# 5. Access the API documentation at http://127.0.0.1:8000/docs
#    or the API itself via endpoints like http://127.0.0.1:8000/person

import logging
from typing import List, Optional, Dict, Any
from datetime import date, datetime, time

# --- Third-party library imports ---
# FastAPI: The web framework for building APIs.
# Pydantic: For data validation and settings management, integrated with FastAPI.
# Faker: For generating fake data.
from fastapi import FastAPI, Query, HTTPException, status
from pydantic import BaseModel, Field, HttpUrl, EmailStr
from faker import Faker
# Importing specific providers for better type hinting and potential future extensions,
# though Faker handles dynamic loading well.
from faker.providers.person.en_US import Provider as PersonProvider
from faker.providers.company.en_US import Provider as CompanyProvider
from faker.providers.address.en_US import Provider as AddressProvider
from faker.providers.internet.en_US import Provider as InternetProvider
from faker.providers.phone_number.en_US import Provider as PhoneNumberProvider
from faker.providers.job.en_US import Provider as JobProvider
from faker.providers.automotive.en_US import Provider as AutomotiveProvider
from faker.providers.lorem.en_US import Provider as LoremProvider
from faker.providers.date_time.en_US import Provider as DateTimeProvider
from faker.providers.color.en_US import Provider as ColorProvider

# --- Application Configuration ---

class AppConfig:
    """
    Configuration class for the API application.
    Defines default settings, limits, and supported locales.
    """
    DEFAULT_LOCALE: str = "en_US"
    # A comprehensive list of supported locales for Faker.
    # This list can be extended or trimmed based on specific requirements.
    SUPPORTED_LOCALES: List[str] = [
        "en_US", "en_GB", "en_CA", "en_AU", "en_NZ", "de_DE", "fr_FR", "es_ES", "it_IT", "ja_JP", "zh_CN", "ar_SA", "ru_RU",
        "pt_BR", "ko_KR", "nl_NL", "sv_SE", "da_DK", "no_NO", "fi_FI", "tr_TR", "pl_PL", "cs_CZ",
        "sk_SK", "hu_HU", "bg_BG", "ro_RO", "el_GR", "th_TH", "vi_VN", "id_ID", "ms_MY", "he_IL",
        "fa_IR", "uk_UA", "et_EE", "lv_LV", "lt_LT", "hr_HR", "sr_RS", "sl_SI", "sq_AL", "mk_MK",
        "hy_AM", "ka_GE", "az_AZ", "kk_KZ", "uz_UZ", "mn_MN", "bn_BD", "ne_NP", "pa_IN", "gu_IN",
        "ta_IN", "te_IN", "kn_IN", "ml_IN", "or_IN", "my_MM", "km_KH", "lo_LA", "sw_KE", "zu_ZA",
        "am_ET", "so_SO", "rw_RW", "ha_NG", "ig_NG", "yo_NG", "en", "fr", "es", "de", "it", "pt",
        "ar", "ru", "ja", "zh", "ko", "nl", "sv", "da", "no", "fi", "tr", "pl", "cs", "sk", "hu",
        "bg", "ro", "el", "th", "vi", "id", "ms", "he", "fa", "uk", "et", "lv", "lt", "hr", "sr",
        "sl", "sq", "mk", "hy", "ka", "az", "kk", "uz", "mn", "bn", "ne", "pa", "gu", "ta", "te",
        "kn", "ml", "or", "my", "km", "lo", "sw", "zu", "am", "so", "rw", "ha", "ig", "yo"
    ]
    MAX_GENERATION_COUNT: int = 100
    MIN_GENERATION_COUNT: int = 1

    _faker_instances: Dict[str, Faker] = {}

    @classmethod
    def get_faker_instance(cls, locale: str) -> Faker:
        """
        Retrieves a Faker instance for the specified locale.
        Caches instances to avoid repeated initialization for performance.
        If the locale is not supported, it falls back to the default locale.
        """
        if locale not in cls.SUPPORTED_LOCALES:
            logger.warning(f"Requested locale '{locale}' not fully supported or invalid. Falling back to '{cls.DEFAULT_LOCALE}'.")
            locale = cls.DEFAULT_LOCALE
        
        if locale not in cls._faker_instances:
            cls._faker_instances[locale] = Faker(locale)
            logger.info(f"Initialized Faker instance for locale: {locale}")
        return cls._faker_instances[locale]

# --- Logging Configuration ---
logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# --- FastAPI Application Initialization ---
app = FastAPI(
    title="Random Data Generator API",
    description="""
    An API wrapper for the 'Faker' library. Provides various endpoints to generate
    diverse types of fake data (e.g., person, company, address, product, internet details)
    for populating test databases, development, and mock APIs.
    
    All endpoints support an optional `locale` query parameter to generate data
    in different languages/regions (e.g., `en_US`, `de_DE`, `fr_FR`).
    A list of supported locales can be retrieved from the `/locales` endpoint.
    """,
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    contact={
        "name": "Random Data Generator Team",
        "url": "https://github.com/your-org/random-data-generator-api", # Placeholder URL
        "email": "contact@example.com", # Placeholder Email
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    }
)

# --- Pydantic Models for API Responses ---
# These models define the structure of the JSON data returned by the API endpoints.
# Each model includes detailed field descriptions and example data for OpenAPI documentation.

class BaseModelWithExamples(BaseModel):
    """
    A base Pydantic model that can be extended by other models
    to automatically include a `schema_extra` for OpenAPI examples.
    """
    class Config:
        json_encoders = {
            date: lambda v: v.isoformat(),
            datetime: lambda v: v.isoformat(),
            time: lambda v: v.isoformat(),
        }

class Person(BaseModelWithExamples):
    """Represents a fake person's basic information."""
    first_name: str = Field(..., example="John", description="The person's first name.")
    last_name: str = Field(..., example="Doe", description="The person's last name.")
    name: str = Field(..., example="Dr. John Doe", description="The person's full name, including title.")
    gender: str = Field(..., example="male", description="The person's gender (e.g., 'male', 'female', 'non-binary').")
    prefix: str = Field(..., example="Mr.", description="A common prefix for the person's name (e.g., Mr., Ms., Dr.).")
    suffix: str = Field(..., example="Jr.", description="A common suffix for the person's name (e.g., Jr., Sr.).")
    title: str = Field(..., example="Engineer", description="A job title for the person.")

    class Config(BaseModelWithExamples.Config):
        schema_extra = {
            "example": {
                "first_name": "Jane",
                "last_name": "Smith",
                "name": "Ms. Jane Smith",
                "gender": "female",
                "prefix": "Ms.",
                "suffix": "III",
                "title": "Software Developer"
            }
        }

class Address(BaseModelWithExamples):
    """Represents a fake address."""
    street_address: str = Field(..., example="123 Main St", description="The full street address.")
    building_number: str = Field(..., example="42B", description="Building number, if applicable.")
    street_name: str = Field(..., example="Oak Avenue", description="The name of the street.")
    street_suffix: str = Field(..., example="Road", description="The type of street (e.g., Road, Avenue).")
    city: str = Field(..., example="Anytown", description="The city name.")
    state: str = Field(..., example="CA", description="The state or province abbreviation.")
    state_full: str = Field(..., example="California", description="The full state or province name.")
    postcode: str = Field(..., example="90210", description="The postal code.")
    country: str = Field(..., example="United States", description="The country name.")
    country_code: str = Field(..., example="US", description="The country's two-letter ISO code.")
    latitude: Optional[float] = Field(None, example=34.052235, description="Geographical latitude.")
    longitude: Optional[float] = Field(None, example=-118.243683, description="Geographical longitude.")

    class Config(BaseModelWithExamples.Config):
        schema_extra = {
            "example": {
                "street_address": "456 Elm Street",
                "building_number": "100",
                "street_name": "Elm",
                "street_suffix": "Street",
                "city": "Springfield",
                "state": "IL",
                "state_full": "Illinois",
                "postcode": "62701",
                "country": "United States",
                "country_code": "US",
                "latitude": 39.798366,
                "longitude": -89.650148
            }
        }

class Contact(BaseModelWithExamples):
    """Represents fake contact information."""
    email: EmailStr = Field(..., example="john.doe@example.com", description="The person's email address.")
    phone_number: str = Field(..., example="+1-555-123-4567", description="The person's phone number.")
    ssn: Optional[str] = Field(None, example="XXX-XX-XXXX", description="Social Security Number (US) or equivalent, if available for locale.")
    blood_group: Optional[str] = Field(None, example="A+", description="Blood group, if available for locale.")
    ean8: Optional[str] = Field(None, example="12345670", description="EAN-8 barcode, if available for locale.")
    ean13: Optional[str] = Field(None, example="1234567890128", description="EAN-13 barcode, if available for locale.")

    class Config(BaseModelWithExamples.Config):
        schema_extra = {
            "example": {
                "email": "jane.smith@domain.net",
                "phone_number": "(555) 987-6543",
                "ssn": "999-88-7777",
                "blood_group": "B-",
                "ean8": "98765432",
                "ean13": "9876543210985"
            }
        }

class Company(BaseModelWithExamples):
    """Represents fake company information."""
    name: str = Field(..., example="Acme Corp", description="The company's name.")
    suffix: str = Field(..., example="Inc.", description="The company's suffix (e.g., Inc., Ltd.).")
    catch_phrase: str = Field(..., example="Innovating the Future", description="A catchy phrase or motto.")
    bs: str = Field(..., example="synergistic strategizing", description="Business 'buzzword' jargon.")
    industry: str = Field(..., example="Technology", description="A general industry classification.")
    slogan: str = Field(..., example="We Build Tomorrow, Today.", description="A marketing slogan for the company.")

    class Config(BaseModelWithExamples.Config):
        schema_extra = {
            "example": {
                "name": "Globex Corporation",
                "suffix": "LLC",
                "catch_phrase": "Reinventing user-centric paradigms",
                "bs": "re-envision business-to-business synergies",
                "industry": "Consulting",
                "slogan": "Your Partner in Progress."
            }
        }

class Job(BaseModelWithExamples):
    """Represents a fake job description."""
    title: str = Field(..., example="Software Engineer", description="The job title.")
    seniority: str = Field(..., example="Senior", description="Seniority level (e.g., Junior, Senior, Lead).")
    field: str = Field(..., example="IT", description="The professional field or industry.")
    skill: str = Field(..., example="Python", description="A specific skill required for the job.")
    salary: Optional[str] = Field(None, example="$120,000", description="An approximate annual salary.")

    class Config(BaseModelWithExamples.Config):
        schema_extra = {
            "example": {
                "title": "Data Scientist",
                "seniority": "Mid-level",
                "field": "Analytics",
                "skill": "Machine Learning",
                "salary": "€85.000"
            }
        }

class Internet(BaseModelWithExamples):
    """Represents fake internet-related data."""
    email: EmailStr = Field(..., example="user@example.com", description="An email address.")
    user_name: str = Field(..., example="johndoe123", description="A username.")
    password: str = Field(..., example="secureP@ssw0rd!", description="A strong password.")
    domain_name: str = Field(..., example="example.com", description="A domain name.")
    domain_word: str = Field(..., example="example", description="The word part of a domain name.")
    url: HttpUrl = Field(..., example="http://www.example.com/path", description="A URL.")
    uri: str = Field(..., example="/path/to/resource", description="A URI.")
    uri_path: str = Field(..., example="/path/to/file.html", description="A URI path.")
    ipv4_address: str = Field(..., example="192.168.1.1", description="An IPv4 address.")
    ipv6_address: str = Field(..., example="2001:0db8:85a3:0000:0000:8a2e:0370:7334", description="An IPv6 address.")
    mac_address: str = Field(..., example="00:1A:2B:3C:4D:5E", description="A MAC address.")
    slug: str = Field(..., example="my-awesome-blog-post", description="A URL-friendly slug.")
    user_agent: str = Field(..., example="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/100.0.4896.75 Safari/537.36", description="A user agent string.")

    class Config(BaseModelWithExamples.Config):
        schema_extra = {
            "example": {
                "email": "jane_d@mail.org",
                "user_name": "janedoe",
                "password": "Pa$$w0rd123",
                "domain_name": "test-site.net",
                "domain_word": "test-site",
                "url": "https://www.test-site.net/products/item-1",
                "uri": "/api/v1/users/profile",
                "uri_path": "/images/logo.png",
                "ipv4_address": "10.0.0.5",
                "ipv6_address": "fe80::1ff:fe23:4567:890a",
                "mac_address": "AB:CD:EF:01:23:45",
                "slug": "another-great-article",
                "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.3 Safari/605.1.15"
            }
        }

class Payment(BaseModelWithExamples):
    """Represents fake payment and financial information."""
    credit_card_number: str = Field(..., example="4242-4242-4242-4242", description="A credit card number.")
    credit_card_provider: str = Field(..., example="Visa", description="Credit card provider (e.g., Visa, MasterCard).")
    credit_card_expire: str = Field(..., example="08/25", description="Credit card expiration date (MM/YY).")
    credit_card_security_code: str = Field(..., example="123", description="Credit card security code (CVV).")
    currency_code: str = Field(..., example="USD", description="Three-letter currency code.")
    currency_name: str = Field(..., example="US Dollar", description="Full currency name.")
    price: str = Field(..., example="$123.45", description="A formatted price string.")
    iban: Optional[str] = Field(None, example="DE89370400440532013000", description="International Bank Account Number (IBAN), if available for locale.")
    swift: Optional[str] = Field(None, example="COMMDEFFXXX", description="SWIFT/BIC code, if available for locale.")

    class Config(BaseModelWithExamples.Config):
        schema_extra = {
            "example": {
                "credit_card_number": "5100-0000-0000-0000",
                "credit_card_provider": "MasterCard",
                "credit_card_expire": "12/26",
                "credit_card_security_code": "456",
                "currency_code": "EUR",
                "currency_name": "Euro",
                "price": "€99.99",
                "iban": "FR7630001007941234567890185",
                "swift": "BNPAFRPPXXX"
            }
        }

class Vehicle(BaseModelWithExamples):
    """Represents fake vehicle information."""
    make: str = Field(..., example="Toyota", description="Vehicle manufacturer.")
    model: str = Field(..., example="Camry", description="Vehicle model.")
    year: int = Field(..., example=2020, description="Model year.")
    color: str = Field(..., example="Silver", description="Vehicle color.")
    license_plate: str = Field(..., example="ABC 123", description="License plate number.")
    vin: str = Field(..., example="1N4AA000000000000", description="Vehicle Identification Number (VIN).")
    category: str = Field(..., example="Sedan", description="Vehicle category (e.g., Sedan, SUV, Truck).")

    class Config(BaseModelWithExamples.Config):
        schema_extra = {
            "example": {
                "make": "Honda",
                "model": "Civic",
                "year": 2022,
                "color": "Red",
                "license_plate": "XYZ 789",
                "vin": "5FNFL3E2XEB000000",
                "category": "Compact"
            }
        }

class Location(BaseModelWithExamples):
    """Represents fake location data, often more detailed than just address."""
    city: str = Field(..., example="New York", description="City name.")
    country: str = Field(..., example="United States", description="Country name.")
    country_code: str = Field(..., example="US", description="Two-letter country code.")
    state: str = Field(..., example="New York", description="State or province name.")
    postcode: str = Field(..., example="10001", description="Postal code.")
    latitude: float = Field(..., example=40.7128, description="Geographical latitude.")
    longitude: float = Field(..., example=-74.0060, description="Geographical longitude.")
    time_zone: str = Field(..., example="America/New_York", description="Time zone name.")
    coordinates: Dict[str, float] = Field(..., example={"lat": 40.7128, "long": -74.0060}, description="Dictionary with latitude and longitude.")
    address: str = Field(..., example="123 Example St, New York, NY 10001", description="Full formatted address string.")

    class Config(BaseModelWithExamples.Config):
        schema_extra = {
            "example": {
                "city": "Los Angeles",
                "country": "United States",
                "country_code": "US",
                "state": "California",
                "postcode": "90210",
                "latitude": 34.0522,
                "longitude": -118.2437,
                "time_zone": "America/Los_Angeles",
                "coordinates": {"lat": 34.0522, "long": -118.2437},
                "address": "456 Hollywood Blvd, Los Angeles, CA 90210"
            }
        }

class DateTimeInfo(BaseModelWithExamples):
    """Represents various fake date and time information."""
    date_object: date = Field(..., example="2023-01-15", description="A random date object.")
    date_time_object: datetime = Field(..., example="2023-01-15T10:30:00Z", description="A random datetime object.")
    time_object: time = Field(..., example="10:30:00", description="A random time object.")
    iso_date: str = Field(..., example="2023-01-15", description="A random date in ISO format (YYYY-MM-DD).")
    iso_date_time: str = Field(..., example="2023-01-15T10:30:00+00:00", description="A random datetime in ISO 8601 format.")
    month_name: str = Field(..., example="January", description="A random month name.")
    day_of_week: str = Field(..., example="Sunday", description="A random day of the week.")
    year: str = Field(..., example="2023", description="A random year.")
    century: str = Field(..., example="XXI", description="A random century (e.g., 'XXI').")
    timezone: str = Field(..., example="Europe/Paris", description="A random timezone name.")

    class Config(BaseModelWithExamples.Config):
        schema_extra = {
            "example": {
                "date_object": "2024-05-20",
                "date_time_object": "2024-05-20T14:45:30Z",
                "time_object": "14:45:30",
                "iso_date": "2024-05-20",
                "iso_date_time": "2024-05-20T14:45:30+00:00",
                "month_name": "May",
                "day_of_week": "Monday",
                "year": "2024",
                "century": "XXI",
                "timezone": "America/New_York"
            }
        }

class ColorInfo(BaseModelWithExamples):
    """Represents fake color information."""
    hex_color: str = Field(..., example="#RRGGBB", description="A random color in hexadecimal format.")
    rgb_color: str = Field(..., example="rgb(R,G,B)", description="A random color in RGB string format.")
    rgb_color_tuple: List[int] = Field(..., example=[255, 0, 0], description="A random color as an RGB list of integers.")
    color_name: str = Field(..., example="Red", description="A common color name.")
    safe_hex_color: str = Field(..., example="#000000", description="A 'web-safe' hexadecimal color.")

    class Config(BaseModelWithExamples.Config):
        schema_extra = {
            "example": {
                "hex_color": "#A0522D",
                "rgb_color": "rgb(160,82,45)",
                "rgb_color_tuple": [160, 82, 45],
                "color_name": "Sienna",
                "safe_hex_color": "#cc3300"
            }
        }

class TextContent(BaseModelWithExamples):
    """Represents fake textual content."""
    word: str = Field(..., example="lorem", description="A single random word.")
    words: List[str] = Field(..., example=["lorem", "ipsum", "dolor"], description="A list of random words.")
    sentence: str = Field(..., example="Lorem ipsum dolor sit amet consectetur adipiscing elit.", description="A random sentence.")
    sentences: List[str] = Field(..., example=["Sentence one.", "Sentence two."], description="A list of random sentences.")
    paragraph: str = Field(..., example="Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua.", description="A random paragraph.")
    paragraphs: List[str] = Field(..., example=["Paragraph one.", "Paragraph two."], description="A list of random paragraphs.")
    text: str = Field(..., example="This is some random text generated by Faker.", description="A block of random text with a specified maximum length.")

    class Config(BaseModelWithExamples.Config):
        schema_extra = {
            "example": {
                "word": "consectetur",
                "words": ["adipisci", "velit", "sed", "quia"],
                "sentence": "Neque porro quisquam est qui dolorem ipsum quia dolor sit amet consectetur adipisci velit.",
                "sentences": ["Et harum quidem rerum facilis est et expedita distinctio.", "Nam libero tempore, cum soluta nobis est eligendi optio cumque nihil impedit quo minus id quod maxime placeat facere possimus."],
                "paragraph": "Ut enim ad minima veniam, quis nostrum exercitationem ullam corporis suscipit laboriosam, nisi ut aliquid ex ea commodi consequatur? Quis autem vel eum iure reprehenderit qui in ea voluptate velit esse quam nihil molestiae consequatur, vel illum qui dolorem eum fugiat quo voluptas nulla pariatur?",
                "paragraphs": ["First paragraph example.", "Second paragraph example."]
            }
        }

class RandomNumbers(BaseModelWithExamples):
    """Represents various types of fake random numbers."""
    random_digit: str = Field(..., example="7", description="A single random digit (0-9).")
    random_digit_not_null: str = Field(..., example="3", description="A single random digit not including zero (1-9).")
    random_int: int = Field(..., example=42, description="A random integer within a default range (0 to 9999).")
    random_number: int = Field(..., example=12345, description="A random number with a specified number of digits.")
    random_float: float = Field(..., example=3.14159, description="A random float number with specified precision.")
    unique_number: int = Field(..., example=98765, description="A unique random number (can be difficult to guarantee uniqueness across many calls).")
    uuid4: str = Field(..., example="a1b2c3d4-e5f6-7890-1234-567890abcdef", description="A UUID version 4 string.")

    class Config(BaseModelWithExamples.Config):
        schema_extra = {
            "example": {
                "random_digit": "9",
                "random_digit_not_null": "1",
                "random_int": 999,
                "random_number": 54321,
                "random_float": 0.12345,
                "unique_number": 102938,
                "uuid4": "fedcba98-7654-3210-fedc-ba9876543210"
            }
        }

class FullPerson(BaseModelWithExamples):
    """Combines various person-related information into a single comprehensive object."""
    personal: Person = Field(..., description="Basic personal details.")
    address_info: Address = Field(..., description="Detailed address information.")
    contact_info: Contact = Field(..., description="Contact details including email and phone.")
    job_info: Job = Field(..., description="Job title and professional details.")
    internet_info: Internet = Field(..., description="Internet presence details like username and URL.")

    class Config(BaseModelWithExamples.Config):
        schema_extra = {
            "example": {
                "personal": Person.Config.schema_extra["example"],
                "address_info": Address.Config.schema_extra["example"],
                "contact_info": Contact.Config.schema_extra["example"],
                "job_info": Job.Config.schema_extra["example"],
                "internet_info": Internet.Config.schema_extra["example"],
            }
        }

# --- Helper Functions for Data Generation ---
# These functions encapsulate the logic for generating a single instance
# of each data type using the Faker library, promoting reusability and clarity.

def _generate_single_person_data(faker: Faker) -> Person:
    """Generates a single fake person's data using the provided Faker instance."""
    return Person(
        first_name=faker.first_name(),
        last_name=faker.last_name(),
        name=faker.name(),
        # Gender is not a standard Faker provider, so we provide a simple fallback
        gender=faker.random_element(elements=('male', 'female', 'non-binary')),
        prefix=faker.prefix(),
        suffix=faker.suffix(),
        title=faker.job() # Using job for a generic title
    )

def _generate_single_address_data(faker: Faker) -> Address:
    """Generates a single fake address data using the provided Faker instance."""
    # Some Faker providers might not have full implementations for all locales.
    # We attempt to provide sensible fallbacks or checks.
    latitude = None
    longitude = None
    try:
        # Faker's latitude/longitude methods return strings, convert to float.
        # Not all locales might have these providers, hence the try-except.
        latitude = float(faker.latitude())
        longitude = float(faker.longitude())
    except AttributeError:
        logger.debug(f"Latitude/longitude provider not available for locale {faker.locale}")
    except ValueError:
        logger.debug(f"Could not convert latitude/longitude to float for locale {faker.locale}")

    return Address(
        street_address=faker.street_address(),
        building_number=faker.building_number(),
        street_name=faker.street_name(),
        street_suffix=faker.street_suffix() if hasattr(faker, 'street_suffix') else faker.word(ext_word_list=['Street', 'Road', 'Avenue', 'Lane']),
        city=faker.city(),
        state=faker.state_abbr(),
        state_full=faker.state(),
        postcode=faker.postcode(),
        country=faker.country(),
        country_code=faker.country_code(),
        latitude=latitude,
        longitude=longitude
    )

def _generate_single_contact_data(faker: Faker) -> Contact:
    """Generates a single fake contact data using the provided Faker instance."""
    # SSN is primarily a US concept. Provide it only if the locale matches and the provider exists.
    ssn = faker.ssn() if hasattr(faker, 'ssn') and faker.locale == "en_US" else None
    return Contact(
        email=faker.email(),
        phone_number=faker.phone_number(),
        ssn=ssn,
        blood_group=faker.blood_group() if hasattr(faker, 'blood_group') else None,
        ean8=faker.ean8() if hasattr(faker, 'ean8') else None,
        ean13=faker.ean13() if hasattr(faker, 'ean13') else None
    )

def _generate_single_company_data(faker: Faker) -> Company:
    """Generates a single fake company data using the provided Faker instance."""
    # The 'job_category' (used as industry) and specific slogan generation might not be available in all locales.
    industry = faker.job_category() if hasattr(faker, 'job_category') else faker.word(ext_word_list=['Technology', 'Finance', 'Healthcare', 'Retail'])
    slogan = faker.sentence(nb_words=6, variable_nb_words=True) # Fallback to generic sentence if specific slogans are not available
    if hasattr(CompanyProvider, 'slogans') and faker.locale == AppConfig.DEFAULT_LOCALE: # Slogans are often locale-specific and might not be defined for all.
        slogan = faker.random_element(elements=CompanyProvider.slogans)

    return Company(
        name=faker.company(),
        suffix=faker.company_suffix(),
        catch_phrase=faker.catch_phrase(),
        bs=faker.bs(),
        industry=industry,
        slogan=slogan
    )

def _generate_single_job_data(faker: Faker) -> Job:
    """Generates a single fake job data using the provided Faker instance."""
    return Job(
        title=faker.job(),
        seniority=faker.random_element(elements=('Junior', 'Mid-level', 'Senior', 'Lead', 'Principal')),
        field=faker.word(ext_word_list=['IT', 'Finance', 'Healthcare', 'Education', 'Marketing', 'Sales', 'Engineering', 'Creative']),
        skill=faker.word(ext_word_list=['Python', 'Java', 'SQL', 'Cloud', 'AI/ML', 'Project Management', 'Communication', 'Design']),
        salary=faker.price(max_value=200000) # Price is a good way to generate a salary-like string
    )

def _generate_single_internet_data(faker: Faker) -> Internet:
    """Generates a single fake internet-related data using the provided Faker instance."""
    return Internet(
        email=faker.email(),
        user_name=faker.user_name(),
        password=faker.password(length=12, special_chars=True, digits=True, upper_case=True, lower_case=True),
        domain_name=faker.domain_name(),
        domain_word=faker.domain_word(),
        url=faker.url(),
        uri=faker.uri(),
        uri_path=faker.uri_path(),
        ipv4_address=faker.ipv4(),
        ipv6_address=faker.ipv6(),
        mac_address=faker.mac_address(),
        slug=faker.slug(),
        user_agent=faker.user_agent()
    )

def _generate_single_payment_data(faker: Faker) -> Payment:
    """Generates a single fake payment/financial data using the provided Faker instance."""
    iban = faker.iban() if hasattr(faker, 'iban') else None
    swift = faker.swift() if hasattr(faker, 'swift') else None
    return Payment(
        credit_card_number=faker.credit_card_number(),
        credit_card_provider=faker.credit_card_provider(),
        credit_card_expire=faker.credit_card_expire(),
        credit_card_security_code=faker.credit_card_security_code(),
        currency_code=faker.currency_code(),
        currency_name=faker.currency_name(),
        price=faker.price(max_value=5000), # Generate a price up to 5000 units
        iban=iban,
        swift=swift
    )

def _generate_single_vehicle_data(faker: Faker) -> Vehicle:
    """Generates a single fake vehicle data using the provided Faker instance."""
    # Ensure automotive provider is available for the current locale.
    # Many locales might not have full automotive data, check for availability.
    # Provide robust fallbacks to ensure the API still returns data.
    if not hasattr(faker, 'license_plate'):
        logger.debug(f"Automotive provider not fully available for locale {faker.locale}, using generic data.")
        return Vehicle(
            make=faker.word(ext_word_list=['GenericMotors', 'AutoCorp']),
            model=faker.word(ext_word_list=['SedanX', 'TruckY']),
            year=faker.random_int(min=1990, max=datetime.now().year + 1),
            color=faker.color_name(),
            license_plate="N/A-" + faker.random_string(length=5, upper_case=True),
            vin="VIN-N/A-" + faker.random_string(length=10, upper_case=True),
            category=faker.random_element(elements=['Sedan', 'SUV', 'Truck'])
        )
    return Vehicle(
        make=faker.vehicle_make(),
        model=faker.vehicle_model(),
        year=int(faker.year()), # Faker's year() returns string
        color=faker.color_name(),
        license_plate=faker.license_plate(),
        vin=faker.vin(),
        category=faker.vehicle_category() if hasattr(faker, 'vehicle_category') else faker.random_element(elements=['Sedan', 'SUV', 'Truck', 'Motorcycle', 'Van'])
    )

def _generate_single_location_data(faker: Faker) -> Location:
    """Generates a single fake location data using the provided Faker instance."""
    # Latitude and longitude are generated as strings, convert them to float for the Pydantic model.
    try:
        latitude = float(faker.latitude())
        longitude = float(faker.longitude())
    except (AttributeError, ValueError):
        logger.debug(f"Latitude/longitude provider not available or invalid for locale {faker.locale}, using defaults.")
        latitude = 0.0
        longitude = 0.0
    
    # Address field can be quite long, limit to a reasonable length for example.
    full_address = faker.address()
    if len(full_address) > 100: # Arbitrary limit for a cleaner example
        full_address = full_address[:97] + "..."

    return Location(
        city=faker.city(),
        country=faker.country(),
        country_code=faker.country_code(),
        state=faker.state(),
        postcode=faker.postcode(),
        latitude=latitude,
        longitude=longitude,
        time_zone=faker.timezone(),
        coordinates={"lat": latitude, "long": longitude},
        address=full_address
    )

def _generate_single_datetime_info(faker: Faker) -> DateTimeInfo:
    """Generates various fake date and time information using the provided Faker instance."""
    generated_datetime = faker.date_time()
    return DateTimeInfo(
        date_object=faker.date_object(),
        date_time_object=generated_datetime,
        time_object=faker.time_object(),
        iso_date=faker.date(),
        iso_date_time=generated_datetime.isoformat(),
        month_name=faker.month_name(),
        day_of_week=faker.day_of_week(),
        year=faker.year(),
        century=faker.century(),
        timezone=faker.timezone()
    )

def _generate_single_color_info(faker: Faker) -> ColorInfo:
    """Generates various fake color information using the provided Faker instance."""
    rgb_str = faker.rgb_color()
    rgb_tuple = [int(x) for x in rgb_str.split(',')] # Convert "R,G,B" to [R,G,B]
    return ColorInfo(
        hex_color=faker.hex_color(),
        rgb_color=rgb_str,
        rgb_color_tuple=rgb_tuple,
        color_name=faker.color_name(),
        safe_hex_color=faker.safe_hex_color()
    )

def _generate_single_text_content(faker: Faker) -> TextContent:
    """Generates various fake textual content using the provided Faker instance."""
    return TextContent(
        word=faker.word(),
        words=faker.words(nb=3),
        sentence=faker.sentence(nb_words=10, variable_nb_words=True),
        sentences=faker.sentences(nb=2),
        paragraph=faker.paragraph(nb_sentences=5, variable_nb_sentences=True),
        paragraphs=faker.paragraphs(nb=2),
        text=faker.text(max_nb_chars=200) # Limits the length of generic text
    )

def _generate_single_random_numbers(faker: Faker) -> RandomNumbers:
    """Generates various types of fake random numbers using the provided Faker instance."""
    return RandomNumbers(
        random_digit=faker.random_digit(),
        random_digit_not_null=faker.random_digit_not_null(),
        random_int=faker.random_int(min=1, max=1000000),
        random_number=faker.random_number(digits=7),
        random_float=faker.pyfloat(left_digits=5, right_digits=4, positive=True, min_value=0.01, max_value=999.99),
        unique_number=faker.unique.random_int(min=10000, max=99999), # Generates a unique number within the Faker session
        uuid4=faker.uuid4()
    )

def _generate_single_full_person_data(faker: Faker) -> FullPerson:
    """
    Generates a comprehensive fake person object by combining other data types
    using their respective single item generation helper functions.
    """
    return FullPerson(
        personal=_generate_single_person_data(faker),
        address_info=_generate_single_address_data(faker),
        contact_info=_generate_single_contact_data(faker),
        job_info=_generate_single_job_data(faker),
        internet_info=_generate_single_internet_data(faker)
    )

def _generate_list_of_items(count: int, generator_func: callable, faker: Faker) -> List[Any]:
    """
    Generates a list of fake data items by repeatedly calling a single-item generator function.
    
    Args:
        count (int): The number of items to generate. Must be within configured limits.
        generator_func (callable): The function to call for generating a single item (e.g., `_generate_single_person_data`).
        faker (Faker): The Faker instance to use for data generation.

    Returns:
        List[Any]: A list of generated items, each conforming to its Pydantic model.
    
    Raises:
        HTTPException: If the requested count is outside the allowed range.
    """
    if not (AppConfig.MIN_GENERATION_COUNT <= count <= AppConfig.MAX_GENERATION_COUNT):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"The 'count' parameter must be between {AppConfig.MIN_GENERATION_COUNT} and {AppConfig.MAX_GENERATION_COUNT}."
        )
    return [generator_func(faker) for _ in range(count)]

# --- API Endpoints ---
# Each endpoint is clearly tagged, described, and includes response models
# for automatic OpenAPI documentation generation.

@app.get("/", summary="Root endpoint - API Information", tags=["General"])
async def root():
    """
    Returns basic information about the Random Data Generator API,
    including its version, description, and links to documentation.
    """
    logger.info("Accessed root endpoint.")
    return {
        "message": "Welcome to the Random Data Generator API!",
        "version": app.version,
        "description": "Generate fake data for your development and testing needs.",
        "documentation_url": str(app.docs_url)
    }

@app.get("/person", response_model=Person, summary="Generate a fake person", tags=["Person"])
async def get_person(
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a single fake person's basic information, including
    first name, last name, full name, gender, prefix, suffix, and a job title.
    """
    logger.info(f"Generating single person for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_single_person_data(faker_instance)

@app.get("/person/list", response_model=List[Person], summary="Generate a list of fake persons", tags=["Person"])
async def get_person_list(
    count: int = Query(1, ge=AppConfig.MIN_GENERATION_COUNT, le=AppConfig.MAX_GENERATION_COUNT,
                       description=f"Number of persons to generate (min {AppConfig.MIN_GENERATION_COUNT}, max {AppConfig.MAX_GENERATION_COUNT})."),
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a list of multiple fake persons, each with basic information.
    The number of persons generated can be controlled using the `count` query parameter.
    """
    logger.info(f"Generating {count} persons for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_list_of_items(count, _generate_single_person_data, faker_instance)

@app.get("/person/full", response_model=FullPerson, summary="Generate a comprehensive fake person profile", tags=["Person"])
async def get_full_person(
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a single, comprehensive fake person profile. This includes
    personal details, address, contact information, job details, and internet presence.
    """
    logger.info(f"Generating full person profile for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_single_full_person_data(faker_instance)

@app.get("/person/full/list", response_model=List[FullPerson], summary="Generate a list of comprehensive fake person profiles", tags=["Person"])
async def get_full_person_list(
    count: int = Query(1, ge=AppConfig.MIN_GENERATION_COUNT, le=AppConfig.MAX_GENERATION_COUNT,
                       description=f"Number of full person profiles to generate (min {AppConfig.MIN_GENERATION_COUNT}, max {AppConfig.MAX_GENERATION_COUNT})."),
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a list of multiple comprehensive fake person profiles.
    Each profile contains personal, address, contact, job, and internet details.
    """
    logger.info(f"Generating {count} full person profiles for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_list_of_items(count, _generate_single_full_person_data, faker_instance)

@app.get("/address", response_model=Address, summary="Generate a fake address", tags=["Location & Address"])
async def get_address(
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a single fake address with detailed components like
    street address, city, state, postal code, country, and geographical coordinates.
    """
    logger.info(f"Generating single address for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_single_address_data(faker_instance)

@app.get("/address/list", response_model=List[Address], summary="Generate a list of fake addresses", tags=["Location & Address"])
async def get_address_list(
    count: int = Query(1, ge=AppConfig.MIN_GENERATION_COUNT, le=AppConfig.MAX_GENERATION_COUNT,
                       description=f"Number of addresses to generate (min {AppConfig.MIN_GENERATION_COUNT}, max {AppConfig.MAX_GENERATION_COUNT})."),
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a list of multiple fake addresses.
    """
    logger.info(f"Generating {count} addresses for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_list_of_items(count, _generate_single_address_data, faker_instance)

@app.get("/contact", response_model=Contact, summary="Generate fake contact information", tags=["Person", "Contact"])
async def get_contact(
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a single set of fake contact information, including
    email, phone number, and potentially SSN or EAN barcodes based on locale availability.
    """
    logger.info(f"Generating single contact info for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_single_contact_data(faker_instance)

@app.get("/contact/list", response_model=List[Contact], summary="Generate a list of fake contact information", tags=["Person", "Contact"])
async def get_contact_list(
    count: int = Query(1, ge=AppConfig.MIN_GENERATION_COUNT, le=AppConfig.MAX_GENERATION_COUNT,
                       description=f"Number of contact items to generate (min {AppConfig.MIN_GENERATION_COUNT}, max {AppConfig.MAX_GENERATION_COUNT})."),
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a list of multiple fake contact information sets.
    """
    logger.info(f"Generating {count} contact info items for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_list_of_items(count, _generate_single_contact_data, faker_instance)

@app.get("/company", response_model=Company, summary="Generate a fake company profile", tags=["Business"])
async def get_company(
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a single fake company profile, including its name, suffix,
    catch phrase, 'BS' jargon, industry, and a marketing slogan.
    """
    logger.info(f"Generating single company for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_single_company_data(faker_instance)

@app.get("/company/list", response_model=List[Company], summary="Generate a list of fake company profiles", tags=["Business"])
async def get_company_list(
    count: int = Query(1, ge=AppConfig.MIN_GENERATION_COUNT, le=AppConfig.MAX_GENERATION_COUNT,
                       description=f"Number of companies to generate (min {AppConfig.MIN_GENERATION_COUNT}, max {AppConfig.MAX_GENERATION_COUNT})."),
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a list of multiple fake company profiles.
    """
    logger.info(f"Generating {count} companies for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_list_of_items(count, _generate_single_company_data, faker_instance)

@app.get("/job", response_model=Job, summary="Generate a fake job description", tags=["Person", "Business"])
async def get_job(
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a single fake job description, comprising a job title,
    seniority level, professional field, and a relevant skill.
    """
    logger.info(f"Generating single job for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_single_job_data(faker_instance)

@app.get("/job/list", response_model=List[Job], summary="Generate a list of fake job descriptions", tags=["Person", "Business"])
async def get_job_list(
    count: int = Query(1, ge=AppConfig.MIN_GENERATION_COUNT, le=AppConfig.MAX_GENERATION_COUNT,
                       description=f"Number of job descriptions to generate (min {AppConfig.MIN_GENERATION_COUNT}, max {AppConfig.MAX_GENERATION_COUNT})."),
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a list of multiple fake job descriptions.
    """
    logger.info(f"Generating {count} jobs for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_list_of_items(count, _generate_single_job_data, faker_instance)

@app.get("/internet", response_model=Internet, summary="Generate fake internet details", tags=["Internet & Tech"])
async def get_internet_details(
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a single set of fake internet-related details, such as
    email, username, strong password, domain information, various URLs/URIs,
    IP addresses, MAC address, URL slug, and a user agent string.
    """
    logger.info(f"Generating single internet details for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_single_internet_data(faker_instance)

@app.get("/internet/list", response_model=List[Internet], summary="Generate a list of fake internet details", tags=["Internet & Tech"])
async def get_internet_details_list(
    count: int = Query(1, ge=AppConfig.MIN_GENERATION_COUNT, le=AppConfig.MAX_GENERATION_COUNT,
                       description=f"Number of internet detail sets to generate (min {AppConfig.MIN_GENERATION_COUNT}, max {AppConfig.MAX_GENERATION_COUNT})."),
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a list of multiple fake internet-related details sets.
    """
    logger.info(f"Generating {count} internet details for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_list_of_items(count, _generate_single_internet_data, faker_instance)

@app.get("/payment", response_model=Payment, summary="Generate fake payment information", tags=["Finance"])
async def get_payment(
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a single set of fake payment and financial information, including
    credit card details (number, provider, expiry, security code),
    currency details, a formatted price, and potentially IBAN/SWIFT codes.
    """
    logger.info(f"Generating single payment info for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_single_payment_data(faker_instance)

@app.get("/payment/list", response_model=List[Payment], summary="Generate a list of fake payment information", tags=["Finance"])
async def get_payment_list(
    count: int = Query(1, ge=AppConfig.MIN_GENERATION_COUNT, le=AppConfig.MAX_GENERATION_COUNT,
                       description=f"Number of payment items to generate (min {AppConfig.MIN_GENERATION_COUNT}, max {AppConfig.MAX_GENERATION_COUNT})."),
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a list of multiple fake payment and financial information sets.
    """
    logger.info(f"Generating {count} payment info items for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_list_of_items(count, _generate_single_payment_data, faker_instance)

@app.get("/vehicle", response_model=Vehicle, summary="Generate fake vehicle information", tags=["Automotive"])
async def get_vehicle(
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a single set of fake vehicle information, such as
    make, model, year, color, license plate number, VIN, and vehicle category.
    """
    logger.info(f"Generating single vehicle for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_single_vehicle_data(faker_instance)

@app.get("/vehicle/list", response_model=List[Vehicle], summary="Generate a list of fake vehicle information", tags=["Automotive"])
async def get_vehicle_list(
    count: int = Query(1, ge=AppConfig.MIN_GENERATION_COUNT, le=AppConfig.MAX_GENERATION_COUNT,
                       description=f"Number of vehicles to generate (min {AppConfig.MIN_GENERATION_COUNT}, max {AppConfig.MAX_GENERATION_COUNT})."),
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a list of multiple fake vehicle information sets.
    """
    logger.info(f"Generating {count} vehicles for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_list_of_items(count, _generate_single_vehicle_data, faker_instance)

@app.get("/location", response_model=Location, summary="Generate fake geographical location data", tags=["Location & Address"])
async def get_location(
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a single set of fake geographical location data, including
    city, country, state, postal code, precise latitude and longitude coordinates,
    timezone, and a full formatted address string.
    """
    logger.info(f"Generating single location for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_single_location_data(faker_instance)

@app.get("/location/list", response_model=List[Location], summary="Generate a list of fake geographical locations", tags=["Location & Address"])
async def get_location_list(
    count: int = Query(1, ge=AppConfig.MIN_GENERATION_COUNT, le=AppConfig.MAX_GENERATION_COUNT,
                       description=f"Number of locations to generate (min {AppConfig.MIN_GENERATION_COUNT}, max {AppConfig.MAX_GENERATION_COUNT})."),
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a list of multiple fake geographical location data sets.
    """
    logger.info(f"Generating {count} locations for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_list_of_items(count, _generate_single_location_data, faker_instance)

@app.get("/datetime", response_model=DateTimeInfo, summary="Generate fake date and time information", tags=["Time & Date"])
async def get_datetime_info(
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a single set of fake date and time information, providing
    various formats like date objects, datetime objects, time objects,
    ISO formatted strings, month names, day of the week, year, century, and timezone.
    """
    logger.info(f"Generating single datetime info for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_single_datetime_info(faker_instance)

@app.get("/datetime/list", response_model=List[DateTimeInfo], summary="Generate a list of fake date and time information", tags=["Time & Date"])
async def get_datetime_info_list(
    count: int = Query(1, ge=AppConfig.MIN_GENERATION_COUNT, le=AppConfig.MAX_GENERATION_COUNT,
                       description=f"Number of datetime items to generate (min {AppConfig.MIN_GENERATION_COUNT}, max {AppConfig.MAX_GENERATION_COUNT})."),
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a list of multiple fake date and time information sets.
    """
    logger.info(f"Generating {count} datetime info for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_list_of_items(count, _generate_single_datetime_info, faker_instance)

@app.get("/color", response_model=ColorInfo, summary="Generate fake color information", tags=["Misc"])
async def get_color_info(
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a single set of fake color information, including
    hexadecimal codes, RGB strings and tuples, common color names, and web-safe hex colors.
    """
    logger.info(f"Generating single color info for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_single_color_info(faker_instance)

@app.get("/color/list", response_model=List[ColorInfo], summary="Generate a list of fake color information", tags=["Misc"])
async def get_color_info_list(
    count: int = Query(1, ge=AppConfig.MIN_GENERATION_COUNT, le=AppConfig.MAX_GENERATION_COUNT,
                       description=f"Number of color items to generate (min {AppConfig.MIN_GENERATION_COUNT}, max {AppConfig.MAX_GENERATION_COUNT})."),
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a list of multiple fake color information sets.
    """
    logger.info(f"Generating {count} color info for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_list_of_items(count, _generate_single_color_info, faker_instance)

@app.get("/text", response_model=TextContent, summary="Generate fake textual content", tags=["Text"])
async def get_text_content(
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a single set of fake textual content, encompassing
    individual words, lists of words, sentences, lists of sentences,
    paragraphs, lists of paragraphs, and general blocks of text.
    """
    logger.info(f"Generating single text content for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_single_text_content(faker_instance)

@app.get("/text/list", response_model=List[TextContent], summary="Generate a list of fake textual content", tags=["Text"])
async def get_text_content_list(
    count: int = Query(1, ge=AppConfig.MIN_GENERATION_COUNT, le=AppConfig.MAX_GENERATION_COUNT,
                       description=f"Number of text content items to generate (min {AppConfig.MIN_GENERATION_COUNT}, max {AppConfig.MAX_GENERATION_COUNT})."),
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a list of multiple fake textual content sets.
    """
    logger.info(f"Generating {count} text content for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_list_of_items(count, _generate_single_text_content, faker_instance)

@app.get("/random_numbers", response_model=RandomNumbers, summary="Generate various fake random numbers and UUIDs", tags=["Misc"])
async def get_random_numbers(
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates various types of fake random numbers and UUIDs, including
    single digits, integers, floats, numbers with specific digit counts,
    and universally unique identifiers (UUIDv4).
    """
    logger.info(f"Generating single random numbers for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_single_random_numbers(faker_instance)

@app.get("/random_numbers/list", response_model=List[RandomNumbers], summary="Generate a list of various fake random numbers and UUIDs", tags=["Misc"])
async def get_random_numbers_list(
    count: int = Query(1, ge=AppConfig.MIN_GENERATION_COUNT, le=AppConfig.MAX_GENERATION_COUNT,
                       description=f"Number of random number sets to generate (min {AppConfig.MIN_GENERATION_COUNT}, max {AppConfig.MAX_GENERATION_COUNT})."),
    locale: str = Query(AppConfig.DEFAULT_LOCALE, description=f"Locale for data generation. E.g., '{AppConfig.DEFAULT_LOCALE}', 'de_DE', 'fr_FR'.")
):
    """
    Generates a list of multiple sets of fake random numbers and UUIDs.
    """
    logger.info(f"Generating {count} random number sets for locale: {locale}")
    faker_instance = AppConfig.get_faker_instance(locale)
    return _generate_list_of_items(count, _generate_single_random_numbers, faker_instance)

@app.get("/locales", summary="Get list of supported locales", tags=["General"])
async def get_supported_locales():
    """
    Returns a comprehensive list of all locales supported by the Faker library
    and this API wrapper. These locales can be used with the `locale` query parameter.
    """
    logger.info("Returning list of supported locales.")
    return {"supported_locales": sorted(AppConfig.SUPPORTED_LOCALES)}

# --- Custom Exception Handling (for illustration) ---
# FastAPI automatically handles HTTPExceptions, but a custom handler can be added
# for specific logging or response formatting needs.
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """
    A custom exception handler for HTTPExceptions.
    Logs the error details before returning the standard FastAPI HTTPException response.
    This can be useful for centralized error logging.
    """
    logger.error(f"HTTP Exception caught: Status {exc.status_code}, Detail: {exc.detail}, Request URL: {request.url}")
    # Re-raise the exception or return a standard JSONResponse if custom formatting is desired.
    # For now, we'll let FastAPI handle the actual response generation for HTTPException.
    # Alternatively, use fastapi.responses.JSONResponse(content={"detail": exc.detail}, status_code=exc.status_code)
    raise exc 

# --- End of Script ---
# To run this script, save it as `main.py` and execute:
# uvicorn main:app --reload --host 0.0.0.0 --port 8000
# The `--reload` flag is useful for development as it restarts the server on code changes.
# `--host 0.0.0.0` makes the server accessible from outside localhost, if desired.