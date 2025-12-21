import os
import datetime
from typing import List, Optional, Union
from uuid import UUID, uuid4

# 3rd party libraries:
# - fastapi: Web framework
# - pydantic: Data validation and settings management
# - asyncpg: PostgreSQL database driver
# - python-dotenv: For loading environment variables from a .env file (optional, but good practice)

# Standard library imports
import logging

# Attempt to load environment variables from a .env file if available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    # dotenv is not strictly necessary for the application to run,
    # but helpful for development setup.
    print("python-dotenv not found, skipping .env loading. Ensure environment variables are set.")

# Initialize logging for the application
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger("inventory_api")

# --- Configuration ---
# Database connection string from environment variables
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://user:password@localhost:5432/inventory_db")
# Default expiry threshold for warranties in days
WARRANTY_EXPIRY_THRESHOLD_DAYS = int(os.getenv("WARRANTY_EXPIRY_THRESHOLD_DAYS", "90"))

# --- Database Setup (using asyncpg) ---
import asyncpg
from asyncpg import Connection, Pool

# Global database connection pool
db_pool: Optional[Pool] = None

async def create_tables_if_not_exists(conn: Connection):
    """
    Creates necessary database tables if they do not already exist.
    This function ensures the database schema is in place on startup.
    """
    logger.info("Checking for database tables and creating if necessary...")
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            username VARCHAR(255) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            full_name VARCHAR(255),
            contact_info TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS locations (
            location_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            name VARCHAR(255) UNIQUE NOT NULL,
            address TEXT NOT NULL,
            city VARCHAR(100),
            state VARCHAR(100),
            zip_code VARCHAR(20),
            description TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS warranties (
            warranty_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            vendor VARCHAR(255) NOT NULL,
            start_date DATE NOT NULL,
            end_date DATE NOT NULL,
            support_contact TEXT,
            notes TEXT,
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS servers (
            server_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            hostname VARCHAR(255) UNIQUE NOT NULL,
            ip_address INET UNIQUE, -- Using INET type for IP addresses
            ram_gb INTEGER NOT NULL,
            cpu_cores INTEGER NOT NULL,
            os VARCHAR(255) NOT NULL,
            status VARCHAR(50) DEFAULT 'operational', -- e.g., 'operational', 'maintenance', 'decommissioned'
            purchase_date DATE,
            notes TEXT,
            user_id UUID REFERENCES users(user_id) ON DELETE SET NULL, -- Who is assigned this server
            location_id UUID REFERENCES locations(location_id) ON DELETE SET NULL, -- Where is it physically located
            warranty_id UUID REFERENCES warranties(warranty_id) ON DELETE SET NULL, -- Associated warranty
            created_at TIMESTAMPTZ DEFAULT NOW(),
            updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        -- Add indexes for common lookup fields to improve performance
        CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
        CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
        CREATE INDEX IF NOT EXISTS idx_servers_hostname ON servers(hostname);
        CREATE INDEX IF NOT EXISTS idx_servers_ip_address ON servers(ip_address);
        CREATE INDEX IF NOT EXISTS idx_servers_user_id ON servers(user_id);
        CREATE INDEX IF NOT EXISTS idx_servers_location_id ON servers(location_id);
        CREATE INDEX IF NOT EXISTS idx_servers_warranty_id ON servers(warranty_id);
        CREATE INDEX IF NOT EXISTS idx_warranties_end_date ON warranties(end_date);
    """)
    logger.info("Database table check and creation complete.")


async def get_db_connection() -> Connection:
    """
    Dependency injector for FastAPI to get a database connection from the pool.
    Yields a connection and ensures it's released back to the pool after use.
    """
    if db_pool is None:
        logger.error("Database pool is not initialized.")
        raise RuntimeError("Database connection pool not initialized.")

    conn: Connection
    async with db_pool.acquire() as conn:
        yield conn


# --- Pydantic Models ---
from pydantic import BaseModel, Field, EmailStr, validator
from datetime import date

# Base models for common attributes
class TimestampMixin(BaseModel):
    """Mixin for models that include creation and update timestamps."""
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.now,
                                          description="Timestamp when the record was created.",
                                          readOnly=True)
    updated_at: datetime.datetime = Field(default_factory=datetime.datetime.now,
                                          description="Timestamp when the record was last updated.",
                                          readOnly=True)

class UserBase(BaseModel):
    """Base schema for user data."""
    username: str = Field(..., min_length=3, max_length=255, example="jsmith",
                          description="Unique username for the user.")
    email: EmailStr = Field(..., example="john.smith@example.com",
                            description="Unique email address for the user.")
    full_name: Optional[str] = Field(None, max_length=255, example="John Smith",
                                     description="Full name of the user.")
    contact_info: Optional[str] = Field(None, example="Phone: 555-1234, Office: A-101",
                                        description="Contact details for the user.")

class UserCreate(UserBase):
    """Schema for creating a new user."""
    pass

class UserUpdate(UserBase):
    """Schema for updating an existing user, all fields are optional."""
    username: Optional[str] = Field(None, min_length=3, max_length=255)
    email: Optional[EmailStr] = None

class UserInDB(UserBase, TimestampMixin):
    """Schema for user data as stored in the database, including UUID and timestamps."""
    user_id: UUID = Field(default_factory=uuid4, example="a1b2c3d4-e5f6-7890-1234-567890abcdef",
                          description="Unique identifier for the user.")

    class Config:
        orm_mode = True # Enables Pydantic to read data directly from database rows/objects

class LocationBase(BaseModel):
    """Base schema for location data."""
    name: str = Field(..., min_length=3, max_length=255, example="Data Center A",
                      description="Unique name for the physical location.")
    address: str = Field(..., example="123 Tech Lane",
                         description="Street address of the location.")
    city: Optional[str] = Field(None, max_length=100, example="Innovate City",
                               description="City where the location is situated.")
    state: Optional[str] = Field(None, max_length=100, example="CA",
                                description="State or province of the location.")
    zip_code: Optional[str] = Field(None, max_length=20, example="90210",
                                   description="Zip or postal code of the location.")
    description: Optional[str] = Field(None, example="Main production data center.",
                                      description="Detailed description of the location.")

class LocationCreate(LocationBase):
    """Schema for creating a new location."""
    pass

class LocationUpdate(LocationBase):
    """Schema for updating an existing location, all fields optional."""
    name: Optional[str] = Field(None, min_length=3, max_length=255)
    address: Optional[str] = None

class LocationInDB(LocationBase, TimestampMixin):
    """Schema for location data as stored in the database, including UUID and timestamps."""
    location_id: UUID = Field(default_factory=uuid4, example="f1e2d3c4-b5a6-9876-5432-10fedcba9876",
                              description="Unique identifier for the location.")

    class Config:
        orm_mode = True

class WarrantyBase(BaseModel):
    """Base schema for warranty data."""
    vendor: str = Field(..., max_length=255, example="Dell",
                        description="Vendor providing the warranty.")
    start_date: date = Field(..., example="2023-01-01",
                            description="Date the warranty coverage begins.")
    end_date: date = Field(..., example="2026-01-01",
                          description="Date the warranty coverage ends.")
    support_contact: Optional[str] = Field(None, example="support@dell.com",
                                           description="Contact information for warranty support.")
    notes: Optional[str] = Field(None, example="Includes 24/7 on-site support.",
                                 description="Additional notes about the warranty.")

    @validator('end_date')
    def validate_end_date_after_start_date(cls, v, values):
        """Ensures the end date is not before the start date."""
        if 'start_date' in values and v < values['start_date']:
            raise ValueError('End date cannot be before start date')
        return v

class WarrantyCreate(WarrantyBase):
    """Schema for creating a new warranty."""
    pass

class WarrantyUpdate(WarrantyBase):
    """Schema for updating an existing warranty, all fields optional."""
    vendor: Optional[str] = Field(None, max_length=255)
    start_date: Optional[date] = None
    end_date: Optional[date] = None

class WarrantyInDB(WarrantyBase, TimestampMixin):
    """Schema for warranty data as stored in the database, including UUID and timestamps."""
    warranty_id: UUID = Field(default_factory=uuid4, example="1a2b3c4d-5e6f-0987-6543-21fedcba9876",
                              description="Unique identifier for the warranty.")

    class Config:
        orm_mode = True

class ServerBase(BaseModel):
    """Base schema for server data."""
    hostname: str = Field(..., min_length=3, max_length=255, example="webserver01",
                          description="Unique hostname for the server.")
    ip_address: Optional[str] = Field(None, regex=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$", example="192.168.1.100",
                                      description="IP address of the server (IPv4 format).")
    ram_gb: int = Field(..., gt=0, example=64,
                        description="Amount of RAM in GB.")
    cpu_cores: int = Field(..., gt=0, example=16,
                           description="Number of CPU cores.")
    os: str = Field(..., max_length=255, example="Ubuntu Server 22.04 LTS",
                    description="Operating system installed on the server.")
    status: str = Field("operational", max_length=50, example="operational",
                        description="Current operational status of the server (e.g., operational, maintenance, decommissioned).")
    purchase_date: Optional[date] = Field(None, example="2023-03-15",
                                         description="Date the server was purchased.")
    notes: Optional[str] = Field(None, example="Used for production web hosting.",
                                 description="Additional notes about the server.")
    user_id: Optional[UUID] = Field(None, example="a1b2c3d4-e5f6-7890-1234-567890abcdef",
                                    description="ID of the user assigned to this server.")
    location_id: Optional[UUID] = Field(None, example="f1e2d3c4-b5a6-9876-5432-10fedcba9876",
                                        description="ID of the physical location of this server.")
    warranty_id: Optional[UUID] = Field(None, example="1a2b3c4d-5e6f-0987-6543-21fedcba9876",
                                        description="ID of the associated warranty for this server.")

class ServerCreate(ServerBase):
    """Schema for creating a new server."""
    pass

class ServerUpdate(ServerBase):
    """Schema for updating an existing server, all fields optional."""
    hostname: Optional[str] = Field(None, min_length=3, max_length=255)
    ip_address: Optional[str] = Field(None, regex=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    ram_gb: Optional[int] = Field(None, gt=0)
    cpu_cores: Optional[int] = Field(None, gt=0)
    os: Optional[str] = Field(None, max_length=255)
    status: Optional[str] = Field(None, max_length=50)
    purchase_date: Optional[date] = None

class ServerInDB(ServerBase, TimestampMixin):
    """Schema for server data as stored in the database, including UUID and timestamps."""
    server_id: UUID = Field(default_factory=uuid4, example="00a11b22-cc33-44dd-ee55-ff66778899aa",
                            description="Unique identifier for the server.")

    class Config:
        orm_mode = True

class ServerWithDetails(ServerInDB):
    """
    Schema for displaying server details including linked user, location, and warranty information.
    This model flattens the related objects into the server response for convenience.
    """
    assigned_user: Optional[UserInDB] = Field(None, description="Detailed information of the assigned user.")
    physical_location: Optional[LocationInDB] = Field(None, description="Detailed information of the physical location.")
    active_warranty: Optional[WarrantyInDB] = Field(None, description="Detailed information of the active warranty.")

    class Config:
        orm_mode = True

# --- FastAPI Application ---
from fastapi import FastAPI, HTTPException, Depends, status, Response
from fastapi.responses import JSONResponse

app = FastAPI(
    title="IT Inventory Management System API",
    description="A SysAdmin API for tracking IT assets like servers, "
                "linking them to users, and tracking physical location or warranty status. "
                "Built with FastAPI and PostgreSQL.",
    version="1.0.0",
)

@app.on_event("startup")
async def startup_event():
    """
    FastAPI startup event handler. Initializes the database connection pool
    and ensures that all necessary tables are created.
    """
    global db_pool
    logger.info("Application startup initiated. Initializing database pool...")
    try:
        db_pool = await asyncpg.create_pool(
            dsn=DATABASE_URL,
            min_size=1,  # Minimum connections in the pool
            max_size=10, # Maximum connections in the pool
            timeout=60,  # Connection timeout in seconds
            command_timeout=60 # Command execution timeout in seconds
        )
        async with db_pool.acquire() as conn:
            await create_tables_if_not_exists(conn)
        logger.info(f"Database pool created successfully with URL: {DATABASE_URL.split('@')[-1]}")
    except Exception as e:
        logger.critical(f"Failed to connect to the database or create tables: {e}", exc_info=True)
        # It's critical to stop the application if the database is unreachable at startup
        raise RuntimeError("Database initialization failed.") from e

@app.on_event("shutdown")
async def shutdown_event():
    """
    FastAPI shutdown event handler. Closes the database connection pool.
    """
    global db_pool
    if db_pool:
        logger.info("Application shutdown initiated. Closing database pool...")
        await db_pool.close()
        logger.info("Database pool closed.")


# --- Database CRUD Operations ---

# Generic Helper for checking UUID existence
async def check_uuid_exists(conn: Connection, table_name: str, id_column: str, entity_id: UUID) -> bool:
    """Helper function to check if a UUID exists in a specified table."""
    query = f"SELECT EXISTS(SELECT 1 FROM {table_name} WHERE {id_column} = $1)"
    return await conn.fetchval(query, entity_id)

# --- User Operations ---

async def create_user_db(conn: Connection, user_data: UserCreate) -> UserInDB:
    """Inserts a new user record into the database."""
    try:
        query = """
            INSERT INTO users (username, email, full_name, contact_info)
            VALUES ($1, $2, $3, $4)
            RETURNING user_id, username, email, full_name, contact_info, created_at, updated_at;
        """
        row = await conn.fetchrow(query,
                                 user_data.username,
                                 user_data.email,
                                 user_data.full_name,
                                 user_data.contact_info)
        if row:
            return UserInDB(**row)
        else:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create user.")
    except asyncpg.exceptions.UniqueViolationError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User with this username or email already exists.")
    except Exception as e:
        logger.error(f"Error creating user: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {e}")

async def get_user_db(conn: Connection, user_id: UUID) -> Optional[UserInDB]:
    """Retrieves a user record by its UUID."""
    query = """
        SELECT user_id, username, email, full_name, contact_info, created_at, updated_at
        FROM users WHERE user_id = $1;
    """
    row = await conn.fetchrow(query, user_id)
    return UserInDB(**row) if row else None

async def get_users_db(conn: Connection, skip: int = 0, limit: int = 100) -> List[UserInDB]:
    """Retrieves a list of user records with pagination."""
    query = """
        SELECT user_id, username, email, full_name, contact_info, created_at, updated_at
        FROM users ORDER BY username LIMIT $1 OFFSET $2;
    """
    rows = await conn.fetch(query, limit, skip)
    return [UserInDB(**row) for row in rows]

async def update_user_db(conn: Connection, user_id: UUID, user_data: UserUpdate) -> Optional[UserInDB]:
    """Updates an existing user record in the database."""
    # Build update query dynamically based on provided fields
    updates = {k: v for k, v in user_data.dict(exclude_unset=True).items() if v is not None}
    if not updates:
        return await get_user_db(conn, user_id) # No changes, return current state

    set_clauses = [f"{k} = ${i+2}" for i, k in enumerate(updates.keys())] # $1 is user_id
    values = list(updates.values())
    values.append(datetime.datetime.now()) # For updated_at
    set_clauses.append("updated_at = $" + str(len(values) + 1)) # Add updated_at last
    values.insert(0, user_id) # user_id is the first parameter

    query = f"""
        UPDATE users
        SET {', '.join(set_clauses)}
        WHERE user_id = $1
        RETURNING user_id, username, email, full_name, contact_info, created_at, updated_at;
    """
    try:
        row = await conn.fetchrow(query, *values)
        return UserInDB(**row) if row else None
    except asyncpg.exceptions.UniqueViolationError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Another user with this username or email already exists.")
    except Exception as e:
        logger.error(f"Error updating user {user_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {e}")

async def delete_user_db(conn: Connection, user_id: UUID) -> bool:
    """Deletes a user record from the database."""
    query = "DELETE FROM users WHERE user_id = $1;"
    result = await conn.execute(query, user_id)
    return result == "DELETE 1"

# --- Location Operations ---

async def create_location_db(conn: Connection, location_data: LocationCreate) -> LocationInDB:
    """Inserts a new location record into the database."""
    try:
        query = """
            INSERT INTO locations (name, address, city, state, zip_code, description)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING location_id, name, address, city, state, zip_code, description, created_at, updated_at;
        """
        row = await conn.fetchrow(query,
                                 location_data.name,
                                 location_data.address,
                                 location_data.city,
                                 location_data.state,
                                 location_data.zip_code,
                                 location_data.description)
        if row:
            return LocationInDB(**row)
        else:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create location.")
    except asyncpg.exceptions.UniqueViolationError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Location with this name already exists.")
    except Exception as e:
        logger.error(f"Error creating location: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {e}")

async def get_location_db(conn: Connection, location_id: UUID) -> Optional[LocationInDB]:
    """Retrieves a location record by its UUID."""
    query = """
        SELECT location_id, name, address, city, state, zip_code, description, created_at, updated_at
        FROM locations WHERE location_id = $1;
    """
    row = await conn.fetchrow(query, location_id)
    return LocationInDB(**row) if row else None

async def get_locations_db(conn: Connection, skip: int = 0, limit: int = 100) -> List[LocationInDB]:
    """Retrieves a list of location records with pagination."""
    query = """
        SELECT location_id, name, address, city, state, zip_code, description, created_at, updated_at
        FROM locations ORDER BY name LIMIT $1 OFFSET $2;
    """
    rows = await conn.fetch(query, limit, skip)
    return [LocationInDB(**row) for row in rows]

async def update_location_db(conn: Connection, location_id: UUID, location_data: LocationUpdate) -> Optional[LocationInDB]:
    """Updates an existing location record in the database."""
    updates = {k: v for k, v in location_data.dict(exclude_unset=True).items() if v is not None}
    if not updates:
        return await get_location_db(conn, location_id)

    set_clauses = [f"{k} = ${i+2}" for i, k in enumerate(updates.keys())]
    values = list(updates.values())
    values.append(datetime.datetime.now())
    set_clauses.append("updated_at = $" + str(len(values) + 1))
    values.insert(0, location_id)

    query = f"""
        UPDATE locations
        SET {', '.join(set_clauses)}
        WHERE location_id = $1
        RETURNING location_id, name, address, city, state, zip_code, description, created_at, updated_at;
    """
    try:
        row = await conn.fetchrow(query, *values)
        return LocationInDB(**row) if row else None
    except asyncpg.exceptions.UniqueViolationError:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Another location with this name already exists.")
    except Exception as e:
        logger.error(f"Error updating location {location_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {e}")

async def delete_location_db(conn: Connection, location_id: UUID) -> bool:
    """Deletes a location record from the database."""
    query = "DELETE FROM locations WHERE location_id = $1;"
    result = await conn.execute(query, location_id)
    return result == "DELETE 1"

# --- Warranty Operations ---

async def create_warranty_db(conn: Connection, warranty_data: WarrantyCreate) -> WarrantyInDB:
    """Inserts a new warranty record into the database."""
    try:
        query = """
            INSERT INTO warranties (vendor, start_date, end_date, support_contact, notes)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING warranty_id, vendor, start_date, end_date, support_contact, notes, created_at, updated_at;
        """
        row = await conn.fetchrow(query,
                                 warranty_data.vendor,
                                 warranty_data.start_date,
                                 warranty_data.end_date,
                                 warranty_data.support_contact,
                                 warranty_data.notes)
        if row:
            return WarrantyInDB(**row)
        else:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create warranty.")
    except Exception as e:
        logger.error(f"Error creating warranty: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {e}")

async def get_warranty_db(conn: Connection, warranty_id: UUID) -> Optional[WarrantyInDB]:
    """Retrieves a warranty record by its UUID."""
    query = """
        SELECT warranty_id, vendor, start_date, end_date, support_contact, notes, created_at, updated_at
        FROM warranties WHERE warranty_id = $1;
    """
    row = await conn.fetchrow(query, warranty_id)
    return WarrantyInDB(**row) if row else None

async def get_warranties_db(conn: Connection, skip: int = 0, limit: int = 100) -> List[WarrantyInDB]:
    """Retrieves a list of warranty records with pagination."""
    query = """
        SELECT warranty_id, vendor, start_date, end_date, support_contact, notes, created_at, updated_at
        FROM warranties ORDER BY end_date DESC LIMIT $1 OFFSET $2;
    """
    rows = await conn.fetch(query, limit, skip)
    return [WarrantyInDB(**row) for row in rows]

async def update_warranty_db(conn: Connection, warranty_id: UUID, warranty_data: WarrantyUpdate) -> Optional[WarrantyInDB]:
    """Updates an existing warranty record in the database."""
    updates = {k: v for k, v in warranty_data.dict(exclude_unset=True).items() if v is not None}
    if not updates:
        return await get_warranty_db(conn, warranty_id)

    set_clauses = [f"{k} = ${i+2}" for i, k in enumerate(updates.keys())]
    values = list(updates.values())
    values.append(datetime.datetime.now())
    set_clauses.append("updated_at = $" + str(len(values) + 1))
    values.insert(0, warranty_id)

    query = f"""
        UPDATE warranties
        SET {', '.join(set_clauses)}
        WHERE warranty_id = $1
        RETURNING warranty_id, vendor, start_date, end_date, support_contact, notes, created_at, updated_at;
    """
    try:
        row = await conn.fetchrow(query, *values)
        return WarrantyInDB(**row) if row else None
    except Exception as e:
        logger.error(f"Error updating warranty {warranty_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {e}")

async def delete_warranty_db(conn: Connection, warranty_id: UUID) -> bool:
    """Deletes a warranty record from the database."""
    query = "DELETE FROM warranties WHERE warranty_id = $1;"
    result = await conn.execute(query, warranty_id)
    return result == "DELETE 1"

async def get_expiring_warranties_db(conn: Connection, days_threshold: int = WARRANTY_EXPIRY_THRESHOLD_DAYS) -> List[WarrantyInDB]:
    """Retrieves warranties that are expiring within a specified number of days."""
    today = datetime.date.today()
    expiry_date_limit = today + datetime.timedelta(days=days_threshold)
    query = """
        SELECT warranty_id, vendor, start_date, end_date, support_contact, notes, created_at, updated_at
        FROM warranties
        WHERE end_date >= $1 AND end_date <= $2
        ORDER BY end_date ASC;
    """
    rows = await conn.fetch(query, today, expiry_date_limit)
    return [WarrantyInDB(**row) for row in rows]

# --- Server Operations ---

async def create_server_db(conn: Connection, server_data: ServerCreate) -> ServerInDB:
    """Inserts a new server record into the database."""
    # Validate foreign keys before inserting
    if server_data.user_id and not await check_uuid_exists(conn, "users", "user_id", server_data.user_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"User with ID {server_data.user_id} not found.")
    if server_data.location_id and not await check_uuid_exists(conn, "locations", "location_id", server_data.location_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Location with ID {server_data.location_id} not found.")
    if server_data.warranty_id and not await check_uuid_exists(conn, "warranties", "warranty_id", server_data.warranty_id):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Warranty with ID {server_data.warranty_id} not found.")

    try:
        query = """
            INSERT INTO servers (hostname, ip_address, ram_gb, cpu_cores, os, status, purchase_date, notes, user_id, location_id, warranty_id)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
            RETURNING server_id, hostname, ip_address, ram_gb, cpu_cores, os, status, purchase_date, notes, user_id, location_id, warranty_id, created_at, updated_at;
        """
        row = await conn.fetchrow(query,
                                 server_data.hostname,
                                 server_data.ip_address,
                                 server_data.ram_gb,
                                 server_data.cpu_cores,
                                 server_data.os,
                                 server_data.status,
                                 server_data.purchase_date,
                                 server_data.notes,
                                 server_data.user_id,
                                 server_data.location_id,
                                 server_data.warranty_id)
        if row:
            return ServerInDB(**row)
        else:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to create server.")
    except asyncpg.exceptions.UniqueViolationError as e:
        if "hostname" in str(e):
            detail = "Server with this hostname already exists."
        elif "ip_address" in str(e):
            detail = "Server with this IP address already exists."
        else:
            detail = "A unique constraint violation occurred."
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)
    except Exception as e:
        logger.error(f"Error creating server: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {e}")

async def get_server_db(conn: Connection, server_id: UUID) -> Optional[ServerInDB]:
    """Retrieves a server record by its UUID."""
    query = """
        SELECT server_id, hostname, ip_address, ram_gb, cpu_cores, os, status, purchase_date, notes, user_id, location_id, warranty_id, created_at, updated_at
        FROM servers WHERE server_id = $1;
    """
    row = await conn.fetchrow(query, server_id)
    return ServerInDB(**row) if row else None

async def get_server_with_details_db(conn: Connection, server_id: UUID) -> Optional[ServerWithDetails]:
    """
    Retrieves a server record by its UUID, including linked user, location, and warranty details.
    Uses a JOIN query to fetch all related data in a single database call.
    """
    query = """
        SELECT
            s.server_id, s.hostname, s.ip_address, s.ram_gb, s.cpu_cores, s.os, s.status, s.purchase_date, s.notes, s.created_at, s.updated_at,
            u.user_id AS user_id, u.username, u.email, u.full_name, u.contact_info, u.created_at AS user_created_at, u.updated_at AS user_updated_at,
            l.location_id AS location_id, l.name AS location_name, l.address, l.city, l.state, l.zip_code, l.description AS location_description, l.created_at AS location_created_at, l.updated_at AS location_updated_at,
            w.warranty_id AS warranty_id, w.vendor, w.start_date, w.end_date, w.support_contact, w.notes AS warranty_notes, w.created_at AS warranty_created_at, w.updated_at AS warranty_updated_at
        FROM servers s
        LEFT JOIN users u ON s.user_id = u.user_id
        LEFT JOIN locations l ON s.location_id = l.location_id
        LEFT JOIN warranties w ON s.warranty_id = w.warranty_id
        WHERE s.server_id = $1;
    """
    row = await conn.fetchrow(query, server_id)
    if row:
        server_data = {
            "server_id": row["server_id"],
            "hostname": row["hostname"],
            "ip_address": row["ip_address"],
            "ram_gb": row["ram_gb"],
            "cpu_cores": row["cpu_cores"],
            "os": row["os"],
            "status": row["status"],
            "purchase_date": row["purchase_date"],
            "notes": row["notes"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "user_id": row["user_id"], # These are FK IDs, not full objects
            "location_id": row["location_id"],
            "warranty_id": row["warranty_id"],
        }
        
        assigned_user = None
        if row["user_id"]: # Check if user_id is not NULL
            assigned_user = UserInDB(
                user_id=row["user_id"],
                username=row["username"],
                email=row["email"],
                full_name=row["full_name"],
                contact_info=row["contact_info"],
                created_at=row["user_created_at"],
                updated_at=row["user_updated_at"]
            )
        
        physical_location = None
        if row["location_id"]: # Check if location_id is not NULL
            physical_location = LocationInDB(
                location_id=row["location_id"],
                name=row["location_name"],
                address=row["address"],
                city=row["city"],
                state=row["state"],
                zip_code=row["zip_code"],
                description=row["location_description"],
                created_at=row["location_created_at"],
                updated_at=row["location_updated_at"]
            )

        active_warranty = None
        if row["warranty_id"]: # Check if warranty_id is not NULL
            active_warranty = WarrantyInDB(
                warranty_id=row["warranty_id"],
                vendor=row["vendor"],
                start_date=row["start_date"],
                end_date=row["end_date"],
                support_contact=row["support_contact"],
                notes=row["warranty_notes"],
                created_at=row["warranty_created_at"],
                updated_at=row["warranty_updated_at"]
            )

        return ServerWithDetails(
            **server_data,
            assigned_user=assigned_user,
            physical_location=physical_location,
            active_warranty=active_warranty
        )
    return None

async def get_servers_db(
    conn: Connection,
    skip: int = 0,
    limit: int = 100,
    user_id: Optional[UUID] = None,
    location_id: Optional[UUID] = None,
    status_filter: Optional[str] = None
) -> List[ServerInDB]:
    """Retrieves a list of server records with pagination and optional filtering."""
    base_query = """
        SELECT server_id, hostname, ip_address, ram_gb, cpu_cores, os, status, purchase_date, notes, user_id, location_id, warranty_id, created_at, updated_at
        FROM servers
    """
    where_clauses = []
    query_params = []
    param_idx = 1

    if user_id:
        where_clauses.append(f"user_id = ${param_idx}")
        query_params.append(user_id)
        param_idx += 1
    if location_id:
        where_clauses.append(f"location_id = ${param_idx}")
        query_params.append(location_id)
        param_idx += 1
    if status_filter:
        where_clauses.append(f"status = ${param_idx}")
        query_params.append(status_filter)
        param_idx += 1
    
    if where_clauses:
        base_query += " WHERE " + " AND ".join(where_clauses)
    
    base_query += f" ORDER BY hostname LIMIT ${param_idx} OFFSET ${param_idx + 1};"
    query_params.extend([limit, skip])

    rows = await conn.fetch(base_query, *query_params)
    return [ServerInDB(**row) for row in rows]

async def update_server_db(conn: Connection, server_id: UUID, server_data: ServerUpdate) -> Optional[ServerInDB]:
    """Updates an existing server record in the database."""
    updates = {k: v for k, v in server_data.dict(exclude_unset=True).items() if v is not None}
    if not updates:
        return await get_server_db(conn, server_id)

    # Validate foreign keys if they are being updated
    if 'user_id' in updates and updates['user_id'] is not None and \
       not await check_uuid_exists(conn, "users", "user_id", updates['user_id']):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"User with ID {updates['user_id']} not found.")
    if 'location_id' in updates and updates['location_id'] is not None and \
       not await check_uuid_exists(conn, "locations", "location_id", updates['location_id']):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Location with ID {updates['location_id']} not found.")
    if 'warranty_id' in updates and updates['warranty_id'] is not None and \
       not await check_uuid_exists(conn, "warranties", "warranty_id", updates['warranty_id']):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Warranty with ID {updates['warranty_id']} not found.")

    set_clauses = [f"{k} = ${i+2}" for i, k in enumerate(updates.keys())]
    values = list(updates.values())
    values.append(datetime.datetime.now())
    set_clauses.append("updated_at = $" + str(len(values) + 1))
    values.insert(0, server_id)

    query = f"""
        UPDATE servers
        SET {', '.join(set_clauses)}
        WHERE server_id = $1
        RETURNING server_id, hostname, ip_address, ram_gb, cpu_cores, os, status, purchase_date, notes, user_id, location_id, warranty_id, created_at, updated_at;
    """
    try:
        row = await conn.fetchrow(query, *values)
        return ServerInDB(**row) if row else None
    except asyncpg.exceptions.UniqueViolationError as e:
        if "hostname" in str(e):
            detail = "Another server with this hostname already exists."
        elif "ip_address" in str(e):
            detail = "Another server with this IP address already exists."
        else:
            detail = "A unique constraint violation occurred during update."
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=detail)
    except Exception as e:
        logger.error(f"Error updating server {server_id}: {e}", exc_info=True)
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Database error: {e}")

async def delete_server_db(conn: Connection, server_id: UUID) -> bool:
    """Deletes a server record from the database."""
    query = "DELETE FROM servers WHERE server_id = $1;"
    result = await conn.execute(query, server_id)
    return result == "DELETE 1"

# --- API Endpoints ---

@app.get("/", tags=["Root"])
async def root():
    """
    Root endpoint for the API. Provides a simple welcome message and links to documentation.
    """
    return {
        "message": "Welcome to the IT Inventory Management System API!",
        "documentation": "/docs",
        "redoc": "/redoc"
    }

# --- User Endpoints ---

@app.post("/users/", response_model=UserInDB, status_code=status.HTTP_201_CREATED, tags=["Users"])
async def create_user(user: UserCreate, conn: Connection = Depends(get_db_connection)):
    """
    Creates a new user record in the inventory system.
    """
    logger.info(f"Attempting to create user: {user.username}")
    new_user = await create_user_db(conn, user)
    logger.info(f"User created with ID: {new_user.user_id}")
    return new_user

@app.get("/users/", response_model=List[UserInDB], tags=["Users"])
async def read_users(
    skip: int = Field(0, ge=0, description="Number of items to skip for pagination."),
    limit: int = Field(100, ge=1, le=200, description="Maximum number of items to return."),
    conn: Connection = Depends(get_db_connection)
):
    """
    Retrieves a list of all users with pagination.
    """
    users = await get_users_db(conn, skip=skip, limit=limit)
    return users

@app.get("/users/{user_id}", response_model=UserInDB, tags=["Users"])
async def read_user(user_id: UUID, conn: Connection = Depends(get_db_connection)):
    """
    Retrieves a single user's details by their unique ID.
    """
    user = await get_user_db(conn, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    return user

@app.put("/users/{user_id}", response_model=UserInDB, tags=["Users"])
async def update_user(user_id: UUID, user_data: UserUpdate, conn: Connection = Depends(get_db_connection)):
    """
    Updates an existing user's details. Only provided fields will be updated.
    """
    logger.info(f"Attempting to update user: {user_id}")
    updated_user = await update_user_db(conn, user_id, user_data)
    if updated_user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    logger.info(f"User {user_id} updated successfully.")
    return updated_user

@app.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Users"])
async def delete_user(user_id: UUID, conn: Connection = Depends(get_db_connection)):
    """
    Deletes a user record from the system.
    Note: Deleting a user will set the `user_id` to NULL for any linked servers (CASCADE SET NULL).
    """
    logger.warning(f"Attempting to delete user: {user_id}")
    deleted = await delete_user_db(conn, user_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")
    logger.info(f"User {user_id} deleted successfully.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# --- Location Endpoints ---

@app.post("/locations/", response_model=LocationInDB, status_code=status.HTTP_201_CREATED, tags=["Locations"])
async def create_location(location: LocationCreate, conn: Connection = Depends(get_db_connection)):
    """
    Creates a new physical location record.
    """
    logger.info(f"Attempting to create location: {location.name}")
    new_location = await create_location_db(conn, location)
    logger.info(f"Location created with ID: {new_location.location_id}")
    return new_location

@app.get("/locations/", response_model=List[LocationInDB], tags=["Locations"])
async def read_locations(
    skip: int = Field(0, ge=0),
    limit: int = Field(100, ge=1, le=200),
    conn: Connection = Depends(get_db_connection)
):
    """
    Retrieves a list of all locations with pagination.
    """
    locations = await get_locations_db(conn, skip=skip, limit=limit)
    return locations

@app.get("/locations/{location_id}", response_model=LocationInDB, tags=["Locations"])
async def read_location(location_id: UUID, conn: Connection = Depends(get_db_connection)):
    """
    Retrieves a single location's details by its unique ID.
    """
    location = await get_location_db(conn, location_id)
    if location is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Location not found.")
    return location

@app.put("/locations/{location_id}", response_model=LocationInDB, tags=["Locations"])
async def update_location(location_id: UUID, location_data: LocationUpdate, conn: Connection = Depends(get_db_connection)):
    """
    Updates an existing location's details. Only provided fields will be updated.
    """
    logger.info(f"Attempting to update location: {location_id}")
    updated_location = await update_location_db(conn, location_id, location_data)
    if updated_location is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Location not found.")
    logger.info(f"Location {location_id} updated successfully.")
    return updated_location

@app.delete("/locations/{location_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Locations"])
async def delete_location(location_id: UUID, conn: Connection = Depends(get_db_connection)):
    """
    Deletes a location record.
    Note: Deleting a location will set the `location_id` to NULL for any linked servers (CASCADE SET NULL).
    """
    logger.warning(f"Attempting to delete location: {location_id}")
    deleted = await delete_location_db(conn, location_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Location not found.")
    logger.info(f"Location {location_id} deleted successfully.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# --- Warranty Endpoints ---

@app.post("/warranties/", response_model=WarrantyInDB, status_code=status.HTTP_201_CREATED, tags=["Warranties"])
async def create_warranty(warranty: WarrantyCreate, conn: Connection = Depends(get_db_connection)):
    """
    Creates a new warranty record.
    """
    logger.info(f"Attempting to create warranty for vendor: {warranty.vendor}")
    new_warranty = await create_warranty_db(conn, warranty)
    logger.info(f"Warranty created with ID: {new_warranty.warranty_id}")
    return new_warranty

@app.get("/warranties/", response_model=List[WarrantyInDB], tags=["Warranties"])
async def read_warranties(
    skip: int = Field(0, ge=0),
    limit: int = Field(100, ge=1, le=200),
    conn: Connection = Depends(get_db_connection)
):
    """
    Retrieves a list of all warranties with pagination.
    """
    warranties = await get_warranties_db(conn, skip=skip, limit=limit)
    return warranties

@app.get("/warranties/expiring-soon", response_model=List[WarrantyInDB], tags=["Warranties"])
async def read_expiring_warranties(
    days_threshold: int = Field(WARRANTY_EXPIRY_THRESHOLD_DAYS, ge=1, description="Number of days until expiry to consider 'expiring soon'."),
    conn: Connection = Depends(get_db_connection)
):
    """
    Retrieves a list of warranties that are expiring within the specified number of days.
    """
    logger.info(f"Fetching warranties expiring within {days_threshold} days.")
    expiring_warranties = await get_expiring_warranties_db(conn, days_threshold=days_threshold)
    return expiring_warranties

@app.get("/warranties/{warranty_id}", response_model=WarrantyInDB, tags=["Warranties"])
async def read_warranty(warranty_id: UUID, conn: Connection = Depends(get_db_connection)):
    """
    Retrieves a single warranty's details by its unique ID.
    """
    warranty = await get_warranty_db(conn, warranty_id)
    if warranty is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Warranty not found.")
    return warranty

@app.put("/warranties/{warranty_id}", response_model=WarrantyInDB, tags=["Warranties"])
async def update_warranty(warranty_id: UUID, warranty_data: WarrantyUpdate, conn: Connection = Depends(get_db_connection)):
    """
    Updates an existing warranty's details. Only provided fields will be updated.
    """
    logger.info(f"Attempting to update warranty: {warranty_id}")
    updated_warranty = await update_warranty_db(conn, warranty_id, warranty_data)
    if updated_warranty is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Warranty not found.")
    logger.info(f"Warranty {warranty_id} updated successfully.")
    return updated_warranty

@app.delete("/warranties/{warranty_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Warranties"])
async def delete_warranty(warranty_id: UUID, conn: Connection = Depends(get_db_connection)):
    """
    Deletes a warranty record.
    Note: Deleting a warranty will set the `warranty_id` to NULL for any linked servers (CASCADE SET NULL).
    """
    logger.warning(f"Attempting to delete warranty: {warranty_id}")
    deleted = await delete_warranty_db(conn, warranty_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Warranty not found.")
    logger.info(f"Warranty {warranty_id} deleted successfully.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# --- Server Endpoints ---

@app.post("/servers/", response_model=ServerInDB, status_code=status.HTTP_201_CREATED, tags=["Servers"])
async def create_server(server: ServerCreate, conn: Connection = Depends(get_db_connection)):
    """
    Creates a new server record in the inventory.
    """
    logger.info(f"Attempting to create server: {server.hostname}")
    new_server = await create_server_db(conn, server)
    logger.info(f"Server created with ID: {new_server.server_id}")
    return new_server

@app.get("/servers/", response_model=List[ServerInDB], tags=["Servers"])
async def read_servers(
    skip: int = Field(0, ge=0),
    limit: int = Field(100, ge=1, le=200),
    user_id: Optional[UUID] = Field(None, description="Filter servers by assigned user ID."),
    location_id: Optional[UUID] = Field(None, description="Filter servers by physical location ID."),
    status_filter: Optional[str] = Field(None, description="Filter servers by operational status (e.g., 'operational', 'maintenance')."),
    conn: Connection = Depends(get_db_connection)
):
    """
    Retrieves a list of all servers with pagination and optional filtering by user, location, or status.
    """
    servers = await get_servers_db(conn, skip=skip, limit=limit, user_id=user_id, location_id=location_id, status_filter=status_filter)
    return servers

@app.get("/servers/{server_id}", response_model=ServerWithDetails, tags=["Servers"])
async def read_server(server_id: UUID, conn: Connection = Depends(get_db_connection)):
    """
    Retrieves a single server's details by its unique ID, including linked user, location, and warranty information.
    """
    server = await get_server_with_details_db(conn, server_id)
    if server is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server not found.")
    return server

@app.put("/servers/{server_id}", response_model=ServerInDB, tags=["Servers"])
async def update_server_full(server_id: UUID, server_data: ServerCreate, conn: Connection = Depends(get_db_connection)):
    """
    Completely replaces an existing server's details. All fields must be provided.
    Use PATCH for partial updates.
    """
    logger.info(f"Attempting to perform full update on server: {server_id}")
    # Convert ServerCreate to ServerUpdate for the update_server_db function
    # A full PUT might imply unsetting fields if not provided, but here we enforce ServerCreate
    # for simplicity, meaning all original fields are required.
    updated_server = await update_server_db(conn, server_id, ServerUpdate(**server_data.dict()))
    if updated_server is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server not found.")
    logger.info(f"Server {server_id} fully updated successfully.")
    return updated_server

@app.patch("/servers/{server_id}", response_model=ServerInDB, tags=["Servers"])
async def update_server_partial(server_id: UUID, server_data: ServerUpdate, conn: Connection = Depends(get_db_connection)):
    """
    Partially updates an existing server's details. Only provided fields will be updated.
    """
    logger.info(f"Attempting to perform partial update on server: {server_id}")
    updated_server = await update_server_db(conn, server_id, server_data)
    if updated_server is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server not found.")
    logger.info(f"Server {server_id} partially updated successfully.")
    return updated_server

@app.delete("/servers/{server_id}", status_code=status.HTTP_204_NO_CONTENT, tags=["Servers"])
async def delete_server(server_id: UUID, conn: Connection = Depends(get_db_connection)):
    """
    Deletes a server record from the system.
    """
    logger.warning(f"Attempting to delete server: {server_id}")
    deleted = await delete_server_db(conn, server_id)
    if not deleted:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server not found.")
    logger.info(f"Server {server_id} deleted successfully.")
    return Response(status_code=status.HTTP_204_NO_CONTENT)

# --- Server Linking Endpoints (for specific updates) ---

class ServerLinkUserRequest(BaseModel):
    user_id: Optional[UUID] = Field(None, description="The ID of the user to link, or null to unlink.")

class ServerLinkLocationRequest(BaseModel):
    location_id: Optional[UUID] = Field(None, description="The ID of the location to link, or null to unlink.")

class ServerLinkWarrantyRequest(BaseModel):
    warranty_id: Optional[UUID] = Field(None, description="The ID of the warranty to link, or null to unlink.")

@app.post("/servers/{server_id}/link-user", response_model=ServerInDB, tags=["Servers"])
async def link_server_to_user(
    server_id: UUID,
    link_request: ServerLinkUserRequest,
    conn: Connection = Depends(get_db_connection)
):
    """
    Links a server to a specific user, or unlinks it if `user_id` is null.
    """
    logger.info(f"Attempting to link server {server_id} to user {link_request.user_id}")
    server_update_data = ServerUpdate(user_id=link_request.user_id)
    updated_server = await update_server_db(conn, server_id, server_update_data)
    if updated_server is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server not found.")
    logger.info(f"Server {server_id} linked to user {link_request.user_id} successfully.")
    return updated_server

@app.post("/servers/{server_id}/link-location", response_model=ServerInDB, tags=["Servers"])
async def link_server_to_location(
    server_id: UUID,
    link_request: ServerLinkLocationRequest,
    conn: Connection = Depends(get_db_connection)
):
    """
    Links a server to a specific physical location, or unlinks it if `location_id` is null.
    """
    logger.info(f"Attempting to link server {server_id} to location {link_request.location_id}")
    server_update_data = ServerUpdate(location_id=link_request.location_id)
    updated_server = await update_server_db(conn, server_id, server_update_data)
    if updated_server is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server not found.")
    logger.info(f"Server {server_id} linked to location {link_request.location_id} successfully.")
    return updated_server

@app.post("/servers/{server_id}/link-warranty", response_model=ServerInDB, tags=["Servers"])
async def link_server_to_warranty(
    server_id: UUID,
    link_request: ServerLinkWarrantyRequest,
    conn: Connection = Depends(get_db_connection)
):
    """
    Links a server to a specific warranty, or unlinks it if `warranty_id` is null.
    """
    logger.info(f"Attempting to link server {server_id} to warranty {link_request.warranty_id}")
    server_update_data = ServerUpdate(warranty_id=link_request.warranty_id)
    updated_server = await update_server_db(conn, server_id, server_update_data)
    if updated_server is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Server not found.")
    logger.info(f"Server {server_id} linked to warranty {link_request.warranty_id} successfully.")
    return updated_server

# To run this application:
# 1. Ensure you have PostgreSQL running and a database named `inventory_db` (or whatever you configure).
# 2. Create a user and grant it privileges to the database.
# 3. Set the DATABASE_URL environment variable, e.g.:
#    export DATABASE_URL="postgresql://user:password@localhost:5432/inventory_db"
#    (or create a .env file with DATABASE_URL="...")
# 4. Install necessary libraries:
#    pip install fastapi "uvicorn[standard]" asyncpg pydantic python-dotenv
# 5. Run with Uvicorn:
#    uvicorn your_script_name:app --reload --host 0.0.0.0 --port 8000
#    (replace `your_script_name` with the actual name of this Python file)
# 6. Access the API documentation at http://localhost:8000/docs (Swagger UI) or http://localhost:8000/redoc (ReDoc).