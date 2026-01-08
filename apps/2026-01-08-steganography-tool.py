# This script requires the 'Pillow' (PIL) and 'stepic' libraries.
# You can install them using pip:
# pip install Pillow stepic

import os
import sys
import base64
import argparse
import logging
from io import BytesIO
from PIL import Image, UnidentifiedImageError
import datetime

# --- Configuration and Constants ---
# ==============================================================================

# Define a custom logger for the application
logger = logging.getLogger("SteganographyTool")

# Define default filenames and markers
DEFAULT_OUTPUT_IMAGE_NAME = "stego_output.png"
DEFAULT_OUTPUT_TEXT_NAME = "extracted_secret.txt"
DEFAULT_OUTPUT_IMAGE_NAME_EXTRACTED = "extracted_secret_image.png"

# Markers to identify the type of hidden data (text vs. image)
# These markers are prepended to the data before embedding.
TEXT_DATA_MARKER = b"__STEGO_TEXT_V1__"
IMAGE_DATA_MARKER = b"__STEGO_IMAGE_V1__"

# Define a maximum file size for embedded data if necessary (conceptual, stepic capacity is complex)
MAX_EMBEDDABLE_DATA_SIZE_BYTES = 5 * 1024 * 1024  # 5 MB as a loose guide

# Supported image formats for input and output
SUPPORTED_INPUT_IMAGE_FORMATS = (".png", ".jpg", ".jpeg", ".bmp", ".gif")
SUPPORTED_OUTPUT_IMAGE_FORMATS = (".png",) # PNG is generally preferred for steganography due to lossless compression

# --- Logging Setup ---
# ==============================================================================

def setup_logging(level=logging.INFO):
    """
    Configures the global logger for the application.
    Messages will be printed to the console.
    """
    logger.setLevel(level)
    
    # Create a console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    
    # Create a formatter and add it to the handler
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )
    console_handler.setFormatter(formatter)
    
    # Add the handler to the logger
    # Ensure no duplicate handlers are added on successive calls
    if not logger.handlers:
        logger.addHandler(console_handler)
    logger.debug("Logging initialized.")

# --- Helper Functions for File and Image Operations ---
# ==============================================================================

def _validate_path_exists(file_path: str, description: str = "file") -> bool:
    """
    Validates if a given file path exists.
    
    Args:
        file_path (str): The path to check.
        description (str): A description of the file for logging purposes.
        
    Returns:
        bool: True if the file exists, False otherwise.
    """
    if not os.path.exists(file_path):
        logger.error(f"Error: The {description} at '{file_path}' does not exist.")
        return False
    logger.debug(f"Validated that {description} '{file_path}' exists.")
    return True

def _validate_path_is_file(file_path: str, description: str = "file") -> bool:
    """
    Validates if a given path points to an actual file.
    
    Args:
        file_path (str): The path to check.
        description (str): A description of the path for logging purposes.
        
    Returns:
        bool: True if the path is a file, False otherwise.
    """
    if not os.path.isfile(file_path):
        logger.error(f"Error: The {description} path '{file_path}' is not a valid file.")
        return False
    logger.debug(f"Validated that {description} '{file_path}' is a file.")
    return True

def _validate_image_format(file_path: str) -> bool:
    """
    Validates if an image file has a supported format based on its extension.
    
    Args:
        file_path (str): The path to the image file.
        
    Returns:
        bool: True if the format is supported, False otherwise.
    """
    _, ext = os.path.splitext(file_path)
    if ext.lower() not in SUPPORTED_INPUT_IMAGE_FORMATS:
        logger.error(f"Error: Image format '{ext}' for '{file_path}' is not supported. "
                     f"Supported formats: {', '.join(SUPPORTED_INPUT_IMAGE_FORMATS)}")
        return False
    logger.debug(f"Validated image format for '{file_path}' as '{ext}'.")
    return True

def _load_image(image_path: str) -> Image.Image | None:
    """
    Loads an image from the specified path using Pillow.
    Handles common errors during image loading.
    
    Args:
        image_path (str): The path to the image file.
        
    Returns:
        PIL.Image.Image | None: The loaded Image object, or None if an error occurred.
    """
    if not _validate_path_exists(image_path, "cover image") or \
       not _validate_path_is_file(image_path, "cover image") or \
       not _validate_image_format(image_path):
        return None
        
    try:
        # Open the image, ensure it's loaded to avoid file handle issues, and convert to RGBA
        # Converting to RGBA ensures a consistent format suitable for steganography,
        # especially for images that might be palette-based or have different modes.
        img = Image.open(image_path).convert("RGBA")
        logger.info(f"Successfully loaded image: '{image_path}' (Mode: {img.mode}, Size: {img.size[0]}x{img.size[1]})")
        return img
    except FileNotFoundError:
        logger.error(f"Error: Image file not found at '{image_path}'.")
        return None
    except UnidentifiedImageError:
        logger.error(f"Error: Could not identify image file at '{image_path}'. It might be corrupted or not an image.")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred while loading image '{image_path}': {e}")
        return None

def _save_image(image: Image.Image, output_path: str) -> bool:
    """
    Saves a Pillow Image object to the specified output path.
    Ensures the output format is PNG for better steganography compatibility.
    
    Args:
        image (PIL.Image.Image): The Image object to save.
        output_path (str): The desired path for the output image.
        
    Returns:
        bool: True if the image was saved successfully, False otherwise.
    """
    if not isinstance(image, Image.Image):
        logger.error("Error: Provided object is not a valid Pillow Image.")
        return False
        
    _, ext = os.path.splitext(output_path)
    if ext.lower() not in SUPPORTED_OUTPUT_IMAGE_FORMATS:
        logger.warning(f"Warning: Output format '{ext}' is not recommended for steganography. "
                       f"Saving as PNG anyway. Consider using a '{SUPPORTED_OUTPUT_IMAGE_FORMATS[0]}' extension.")
    
    # Force extension to .png if not already, to ensure lossless output
    if ext.lower() != ".png":
        output_path = os.path.splitext(output_path)[0] + ".png"
        logger.info(f"Output image path adjusted to '{output_path}' to ensure PNG format.")

    try:
        image.save(output_path, format="PNG")
        logger.info(f"Successfully saved image to: '{output_path}'")
        return True
    except Exception as e:
        logger.error(f"Error saving image to '{output_path}': {e}")
        return False

def _read_file_content(file_path: str, mode: str = 'r', encoding: str = 'utf-8') -> bytes | str | None:
    """
    Reads the content of a file, either as text or raw bytes.
    
    Args:
        file_path (str): The path to the file.
        mode (str): File open mode ('r' for text, 'rb' for bytes).
        encoding (str): Encoding to use if mode is 'r'.
        
    Returns:
        bytes | str | None: The content of the file, or None if an error occurred.
    """
    if not _validate_path_exists(file_path, "secret file") or \
       not _validate_path_is_file(file_path, "secret file"):
        return None

    try:
        with open(file_path, mode, encoding=encoding if 'b' not in mode else None) as f:
            content = f.read()
            logger.info(f"Successfully read content from '{file_path}' (Mode: {mode}).")
            return content
    except FileNotFoundError:
        logger.error(f"Error: Secret file not found at '{file_path}'.")
        return None
    except IOError as e:
        logger.error(f"Error reading secret file '{file_path}': {e}")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred while reading '{file_path}': {e}")
        return None

def _write_file_content(content: bytes | str, output_path: str, mode: str = 'w', encoding: str = 'utf-8') -> bool:
    """
    Writes content (text or bytes) to a specified file path.
    
    Args:
        content (bytes | str): The content to write.
        output_path (str): The path where the content should be written.
        mode (str): File open mode ('w' for text, 'wb' for bytes).
        encoding (str): Encoding to use if mode is 'w'.
        
    Returns:
        bool: True if content was written successfully, False otherwise.
    """
    try:
        with open(output_path, mode, encoding=encoding if 'b' not in mode else None) as f:
            f.write(content)
            logger.info(f"Successfully wrote content to '{output_path}' (Mode: {mode}).")
            return True
    except IOError as e:
        logger.error(f"Error writing to output file '{output_path}': {e}")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred while writing to '{output_path}': {e}")
        return False

def _image_to_base64(image_path: str) -> bytes | None:
    """
    Converts an image file into a base64 encoded byte string.
    This is used to embed an image as 'text' data within another image.
    
    Args:
        image_path (str): The path to the image file to encode.
        
    Returns:
        bytes | None: The base64 encoded bytes, or None if an error occurred.
    """
    if not _validate_path_exists(image_path, "secret image") or \
       not _validate_path_is_file(image_path, "secret image") or \
       not _validate_image_format(image_path):
        return None

    try:
        with open(image_path, "rb") as image_file:
            encoded_string = base64.b64encode(image_file.read())
            logger.info(f"Successfully converted image '{image_path}' to base64 string.")
            return encoded_string
    except FileNotFoundError:
        logger.error(f"Error: Secret image file not found at '{image_path}'.")
        return None
    except IOError as e:
        logger.error(f"Error reading secret image '{image_path}': {e}")
        return None
    except Exception as e:
        logger.error(f"An unexpected error occurred during base64 encoding of '{image_path}': {e}")
        return None

def _base64_to_image(base64_string: bytes, output_path: str) -> bool:
    """
    Decodes a base64 encoded byte string back into an image file.
    
    Args:
        base64_string (bytes): The base64 encoded image data.
        output_path (str): The desired path for the decoded image file.
        
    Returns:
        bool: True if the image was successfully decoded and saved, False otherwise.
    """
    try:
        decoded_image_data = base64.b64decode(base64_string)
        img = Image.open(BytesIO(decoded_image_data))
        
        # Ensure the output path has an image extension, default to .png if not provided
        if not os.path.splitext(output_path)[1]:
            output_path += ".png"
            logger.info(f"Output path for image adjusted to '{output_path}' with .png extension.")

        # If the image was originally a different format, we might try to save it as that.
        # However, for consistency and avoiding potential issues, saving as PNG is robust.
        return _save_image(img, output_path)
    except base64.binascii.Error:
        logger.error("Error: Invalid base64 string provided for image decoding.")
        return False
    except UnidentifiedImageError:
        logger.error("Error: Could not identify image from decoded base64 data. Data might be corrupted or not an image.")
        return False
    except Exception as e:
        logger.error(f"An unexpected error occurred during base64 decoding to image '{output_path}': {e}")
        return False

def _get_file_size_bytes(file_path: str) -> int:
    """
    Returns the size of a file in bytes.
    
    Args:
        file_path (str): The path to the file.
        
    Returns:
        int: The file size in bytes, or -1 if the file doesn't exist.
    """
    if not os.path.exists(file_path):
        return -1
    return os.path.getsize(file_path)

def _estimate_stepic_capacity(image: Image.Image) -> int:
    """
    Provides a *very rough* estimate of the maximum data capacity for stepic.
    Stepic (LSB steganography) typically uses 1 bit per color channel. For an RGBA image,
    that's 4 bits per pixel, or 0.5 bytes per pixel. This is an upper bound and depends
    heavily on the image's "noise" and ability to hide data without visual artifacts.
    
    Args:
        image (PIL.Image.Image): The cover image.
        
    Returns:
        int: Estimated maximum bytes that can be embedded.
    """
    width, height = image.size
    # Assuming 4 bytes (RGBA) per pixel and using 1 bit from each channel.
    # So 4 bits per pixel, which is 0.5 bytes per pixel.
    # stepic's actual capacity can be less due to its implementation details
    # and the need for specific pixel value changes.
    estimated_bytes = int(width * height * 0.5)
    logger.debug(f"Estimated steganography capacity for image {width}x{height} "
                 f"is approximately {estimated_bytes / 1024:.2f} KB.")
    return estimated_bytes

# --- Core Steganography Functions ---
# ==============================================================================

def embed_text_in_image(
    cover_image_path: str,
    secret_text_file_path: str,
    output_image_path: str = DEFAULT_OUTPUT_IMAGE_NAME
) -> bool:
    """
    Embeds the content of a secret text file into a cover image using stepic.
    
    Args:
        cover_image_path (str): Path to the image file that will hide the secret.
        secret_text_file_path (str): Path to the text file containing the secret message.
        output_image_path (str): Path where the steganographic image will be saved.
        
    Returns:
        bool: True if the text was successfully embedded, False otherwise.
    """
    logger.info(f"Attempting to embed text from '{secret_text_file_path}' into '{cover_image_path}'.")

    # 1. Load the cover image
    cover_image = _load_image(cover_image_path)
    if cover_image is None:
        logger.error("Failed to load cover image. Embedding aborted.")
        return False

    # 2. Read the secret text file content
    secret_text_bytes = _read_file_content(secret_text_file_path, mode='rb')
    if secret_text_bytes is None:
        logger.error("Failed to read secret text file content. Embedding aborted.")
        return False
        
    # 3. Add a marker to identify the data type upon extraction
    data_to_embed = TEXT_DATA_MARKER + secret_text_bytes
    
    # 4. Perform a rough capacity check
    estimated_capacity = _estimate_stepic_capacity(cover_image)
    if len(data_to_embed) > estimated_capacity:
        logger.warning(f"Warning: The secret data size ({len(data_to_embed) / 1024:.2f} KB) "
                       f"might exceed the estimated capacity of the cover image ({estimated_capacity / 1024:.2f} KB). "
                       f"Embedding might fail or result in data loss/corruption.")
    
    if len(data_to_embed) > MAX_EMBEDDABLE_DATA_SIZE_BYTES:
         logger.warning(f"Warning: The secret data size ({len(data_to_embed) / (1024*1024):.2f} MB) "
                        f"is very large. This might lead to noticeable artifacts or errors. "
                        f"Consider a smaller secret or larger cover image.")

    # 5. Embed the data using stepic
    try:
        import stepic
        stego_image = stepic.encode(cover_image, data_to_embed)
        logger.info(f"Text data successfully embedded into image.")
        
        # 6. Save the steganographic image
        if _save_image(stego_image, output_image_path):
            logger.info(f"Steganographic image saved to '{output_image_path}'.")
            return True
        else:
            logger.error("Failed to save the steganographic image.")
            return False
            
    except ImportError:
        logger.error("Error: 'stepic' library not found. Please install it using 'pip install stepic'.")
        return False
    except Exception as e:
        logger.error(f"An error occurred during text embedding: {e}")
        return False

def embed_image_in_image(
    cover_image_path: str,
    secret_image_path: str,
    output_image_path: str = DEFAULT_OUTPUT_IMAGE_NAME
) -> bool:
    """
    Embeds a secret image into a cover image by first converting the secret
    image to a base64 string, then embedding that string using stepic.
    
    Args:
        cover_image_path (str): Path to the image file that will hide the secret.
        secret_image_path (str): Path to the image file to be hidden.
        output_image_path (str): Path where the steganographic image will be saved.
        
    Returns:
        bool: True if the image was successfully embedded, False otherwise.
    """
    logger.info(f"Attempting to embed image from '{secret_image_path}' into '{cover_image_path}'.")

    # 1. Load the cover image
    cover_image = _load_image(cover_image_path)
    if cover_image is None:
        logger.error("Failed to load cover image. Embedding aborted.")
        return False

    # 2. Convert the secret image to a base64 encoded byte string
    secret_image_base64_bytes = _image_to_base64(secret_image_path)
    if secret_image_base64_bytes is None:
        logger.error("Failed to convert secret image to base64. Embedding aborted.")
        return False

    # 3. Add a marker to identify the data type upon extraction
    data_to_embed = IMAGE_DATA_MARKER + secret_image_base64_bytes
    
    # 4. Perform a rough capacity check
    estimated_capacity = _estimate_stepic_capacity(cover_image)
    if len(data_to_embed) > estimated_capacity:
        logger.warning(f"Warning: The secret image data size ({len(data_to_embed) / 1024:.2f} KB) "
                       f"might exceed the estimated capacity of the cover image ({estimated_capacity / 1024:.2f} KB). "
                       f"Embedding might fail or result in data loss/corruption.")
                       
    if len(data_to_embed) > MAX_EMBEDDABLE_DATA_SIZE_BYTES:
         logger.warning(f"Warning: The secret image data size ({len(data_to_embed) / (1024*1024):.2f} MB) "
                        f"is very large. This might lead to noticeable artifacts or errors. "
                        f"Consider a smaller secret or larger cover image.")

    # 5. Embed the data using stepic
    try:
        import stepic
        stego_image = stepic.encode(cover_image, data_to_embed)
        logger.info(f"Image data successfully embedded into image.")
        
        # 6. Save the steganographic image
        if _save_image(stego_image, output_image_path):
            logger.info(f"Steganographic image saved to '{output_image_path}'.")
            return True
        else:
            logger.error("Failed to save the steganographic image.")
            return False
            
    except ImportError:
        logger.error("Error: 'stepic' library not found. Please install it using 'pip install stepic'.")
        return False
    except Exception as e:
        logger.error(f"An error occurred during image embedding: {e}")
        return False

def extract_data_from_image(
    stego_image_path: str,
    output_path: str = None
) -> bool:
    """
    Extracts hidden data from a steganographic image. It attempts to identify
    whether the hidden data is a text file or a base64 encoded image using markers.
    
    Args:
        stego_image_path (str): Path to the steganographic image.
        output_path (str, optional): Desired path for the extracted data. 
                                     If None, a default filename will be used based on data type.
        
    Returns:
        bool: True if data was successfully extracted and saved, False otherwise.
    """
    logger.info(f"Attempting to extract data from '{stego_image_path}'.")

    # 1. Load the steganographic image
    stego_image = _load_image(stego_image_path)
    if stego_image is None:
        logger.error("Failed to load steganographic image. Extraction aborted.")
        return False

    # 2. Extract data using stepic
    try:
        import stepic
        extracted_data_bytes = stepic.decode(stego_image)
        
        if not extracted_data_bytes:
            logger.warning("No hidden data found or extracted data is empty.")
            return False
            
        logger.info(f"Successfully extracted data (size: {len(extracted_data_bytes)} bytes) from image.")

        # 3. Determine data type and save accordingly
        if extracted_data_bytes.startswith(TEXT_DATA_MARKER):
            logger.info("Detected hidden data as TEXT.")
            actual_text_bytes = extracted_data_bytes[len(TEXT_DATA_MARKER):]
            
            # Use default text output name if not specified
            if not output_path:
                output_path = DEFAULT_OUTPUT_TEXT_NAME
                logger.info(f"No output path specified for text, defaulting to '{output_path}'.")

            # Try to decode as UTF-8, fall back to latin-1 if it fails
            try:
                extracted_text = actual_text_bytes.decode('utf-8')
            except UnicodeDecodeError:
                logger.warning("UTF-8 decoding failed, attempting latin-1.")
                extracted_text = actual_text_bytes.decode('latin-1')

            return _write_file_content(extracted_text, output_path, mode='w', encoding='utf-8')
            
        elif extracted_data_bytes.startswith(IMAGE_DATA_MARKER):
            logger.info("Detected hidden data as IMAGE (base64 encoded).")
            actual_image_base64_bytes = extracted_data_bytes[len(IMAGE_DATA_MARKER):]
            
            # Use default image output name if not specified
            if not output_path:
                output_path = DEFAULT_OUTPUT_IMAGE_NAME_EXTRACTED
                logger.info(f"No output path specified for image, defaulting to '{output_path}'.")
                
            return _base64_to_image(actual_image_base64_bytes, output_path)
            
        else:
            logger.warning("Unknown data marker or no recognizable marker found. "
                           "Attempting to save as raw text (UTF-8, then latin-1 fallback).")
            
            # If no marker, assume it's just raw text or unknown binary and save as such.
            if not output_path:
                output_path = f"unknown_extracted_data_{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}.bin"
                logger.info(f"No output path specified, saving unknown data to '{output_path}'.")

            # Try to decode as UTF-8, fall back to latin-1 if it fails, otherwise save as binary
            try:
                extracted_content = extracted_data_bytes.decode('utf-8')
                return _write_file_content(extracted_content, output_path, mode='w', encoding='utf-8')
            except UnicodeDecodeError:
                logger.warning("Unknown data is not UTF-8 decodable. Attempting latin-1.")
                try:
                    extracted_content = extracted_data_bytes.decode('latin-1')
                    return _write_file_content(extracted_content, output_path, mode='w', encoding='latin-1')
                except UnicodeDecodeError:
                    logger.warning("Unknown data is not latin-1 decodable. Saving as raw binary.")
                    return _write_file_content(extracted_data_bytes, output_path, mode='wb')

    except ImportError:
        logger.error("Error: 'stepic' library not found. Please install it using 'pip install stepic'.")
        return False
    except Exception as e:
        logger.error(f"An error occurred during data extraction: {e}")
        return False

# --- Command Line Interface (CLI) Setup ---
# ==============================================================================

def main():
    """
    Main function to parse command-line arguments and execute the steganography operations.
    """
    setup_logging(level=logging.INFO) # Set default logging level

    parser = argparse.ArgumentParser(
        description="A cybersecurity utility for embedding and extracting secret data within images.",
        formatter_class=argparse.RawTextHelpFormatter # Preserve newlines in help
    )

    # Global options
    parser.add_argument(
        "-v", "--verbose", action="store_true",
        help="Enable verbose output (DEBUG level logging)."
    )

    subparsers = parser.add_subparsers(
        dest="command", required=True,
        help="Choose a command: 'embed-text', 'embed-image', or 'extract'."
    )

    # --- Embed Text Command ---
    embed_text_parser = subparsers.add_parser(
        "embed-text",
        help="Embed a secret text file into a cover image.",
        description="This command embeds the content of a specified text file into a cover image. "
                    "The output will be a new image file containing the hidden text."
    )
    embed_text_parser.add_argument(
        "-c", "--cover-image", type=str, required=True,
        help="Path to the cover image file (e.g., 'path/to/cover.png')."
    )
    embed_text_parser.add_argument(
        "-s", "--secret-file", type=str, required=True,
        help="Path to the secret text file to embed (e.g., 'path/to/secret.txt')."
    )
    embed_text_parser.add_argument(
        "-o", "--output-image", type=str, default=DEFAULT_OUTPUT_IMAGE_NAME,
        help=f"Path for the output steganographic image (default: '{DEFAULT_OUTPUT_IMAGE_NAME}')."
    )

    # --- Embed Image Command ---
    embed_image_parser = subparsers.add_parser(
        "embed-image",
        help="Embed a secret image into a cover image.",
        description="This command embeds one image (the secret) inside another image (the cover). "
                    "The secret image is first converted to a base64 string before embedding. "
                    "The output will be a new image file containing the hidden image."
    )
    embed_image_parser.add_argument(
        "-c", "--cover-image", type=str, required=True,
        help="Path to the cover image file (e.g., 'path/to/cover.png')."
    )
    embed_image_parser.add_argument(
        "-s", "--secret-image", type=str, required=True,
        help="Path to the secret image file to embed (e.g., 'path/to/secret.jpg')."
    )
    embed_image_parser.add_argument(
        "-o", "--output-image", type=str, default=DEFAULT_OUTPUT_IMAGE_NAME,
        help=f"Path for the output steganographic image (default: '{DEFAULT_OUTPUT_IMAGE_NAME}')."
    )

    # --- Extract Command ---
    extract_parser = subparsers.add_parser(
        "extract",
        help="Extract hidden data from a steganographic image.",
        description="This command extracts hidden data (either text or a base64 encoded image) "
                    "from a steganographic image. It attempts to automatically determine the "
                    "original data type and save it to an appropriate file."
    )
    extract_parser.add_argument(
        "-i", "--input-image", type=str, required=True,
        help="Path to the steganographic image containing hidden data (e.g., 'path/to/stego.png')."
    )
    extract_parser.add_argument(
        "-o", "--output-file", type=str,
        help=f"Path for the extracted secret data (e.g., 'path/to/extracted.txt' or 'path/to/extracted.png'). "
             f"If not provided, a default name like '{DEFAULT_OUTPUT_TEXT_NAME}' or "
             f"'{DEFAULT_OUTPUT_IMAGE_NAME_EXTRACTED}' will be used based on the detected data type."
    )

    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Verbose logging enabled.")

    success = False
    if args.command == "embed-text":
        logger.debug("Executing 'embed-text' command.")
        success = embed_text_in_image(args.cover_image, args.secret_file, args.output_image)
    elif args.command == "embed-image":
        logger.debug("Executing 'embed-image' command.")
        success = embed_image_in_image(args.cover_image, args.secret_image, args.output_image)
    elif args.command == "extract":
        logger.debug("Executing 'extract' command.")
        success = extract_data_from_image(args.input_image, args.output_file)
    
    if success:
        logger.info(f"Operation '{args.command}' completed successfully.")
        sys.exit(0)
    else:
        logger.error(f"Operation '{args.command}' failed.")
        sys.exit(1)

# --- Entry Point ---
# ==============================================================================

if __name__ == "__main__":
    # Ensure all necessary modules are available or provide a helpful error.
    try:
        import PIL
        import stepic
    except ImportError as e:
        sys.exit(f"Error: Required library not found. Please install with 'pip install Pillow stepic'. Detail: {e}")

    main()