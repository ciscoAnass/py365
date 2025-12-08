import os
import sys
import json
import logging
import traceback
from typing import Dict, Any, Optional, Tuple
from pathlib import Path
from datetime import datetime
from functools import wraps
import hashlib
import mimetypes

from flask import Flask, request, jsonify, send_file, Response
from jinja2 import Environment, FileSystemLoader, TemplateNotFound, TemplateSyntaxError
import weasyprint
from io import BytesIO
import uuid

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

app = Flask(__name__)

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), 'templates')
OUTPUT_DIR = os.path.join(os.path.dirname(__file__), 'output')
CACHE_DIR = os.path.join(os.path.dirname(__file__), 'cache')
MAX_CONTENT_LENGTH = 16 * 1024 * 1024

app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

for directory in [TEMPLATES_DIR, OUTPUT_DIR, CACHE_DIR]:
    Path(directory).mkdir(parents=True, exist_ok=True)

jinja_env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=True,
    trim_blocks=True,
    lstrip_blocks=True
)

jinja_env.filters['currency'] = lambda x: f"${x:,.2f}" if isinstance(x, (int, float)) else x
jinja_env.filters['date_format'] = lambda x: datetime.strptime(x, '%Y-%m-%d').strftime('%B %d, %Y') if isinstance(x, str) else x
jinja_env.filters['uppercase'] = lambda x: str(x).upper()
jinja_env.filters['lowercase'] = lambda x: str(x).lower()
jinja_env.filters['title_case'] = lambda x: str(x).title()


def validate_json_data(data: Any) -> Tuple[bool, Optional[str]]:
    """
    Validate that the provided data is valid JSON-serializable content.
    
    Args:
        data: The data to validate
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        if not isinstance(data, dict):
            return False, "Data must be a dictionary/object"
        
        json.dumps(data)
        return True, None
    except (TypeError, ValueError) as e:
        return False, f"Invalid JSON data: {str(e)}"


def validate_template_name(template_name: str) -> Tuple[bool, Optional[str]]:
    """
    Validate that the template name is safe and exists.
    
    Args:
        template_name: The name of the template file
        
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not template_name:
        return False, "Template name cannot be empty"
    
    if '..' in template_name or '/' in template_name or '\\' in template_name:
        return False, "Invalid template name: path traversal detected"
    
    template_path = os.path.join(TEMPLATES_DIR, template_name)
    
    if not os.path.exists(template_path):
        return False, f"Template '{template_name}' not found"
    
    if not template_path.startswith(os.path.abspath(TEMPLATES_DIR)):
        return False, "Invalid template path"
    
    return True, None


def generate_cache_key(template_name: str, data: Dict[str, Any]) -> str:
    """
    Generate a cache key based on template name and data.
    
    Args:
        template_name: The template file name
        data: The data dictionary
        
    Returns:
        A unique cache key string
    """
    content = f"{template_name}:{json.dumps(data, sort_keys=True)}"
    return hashlib.md5(content.encode()).hexdigest()


def get_cached_pdf(cache_key: str) -> Optional[bytes]:
    """
    Retrieve a cached PDF if it exists.
    
    Args:
        cache_key: The cache key
        
    Returns:
        PDF bytes if cached, None otherwise
    """
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.pdf")
    
    if os.path.exists(cache_file):
        try:
            with open(cache_file, 'rb') as f:
                logger.info(f"Retrieved PDF from cache: {cache_key}")
                return f.read()
        except Exception as e:
            logger.warning(f"Failed to read cached PDF: {str(e)}")
            return None
    
    return None


def cache_pdf(cache_key: str, pdf_bytes: bytes) -> bool:
    """
    Cache a generated PDF.
    
    Args:
        cache_key: The cache key
        pdf_bytes: The PDF content as bytes
        
    Returns:
        True if caching was successful, False otherwise
    """
    cache_file = os.path.join(CACHE_DIR, f"{cache_key}.pdf")
    
    try:
        with open(cache_file, 'wb') as f:
            f.write(pdf_bytes)
        logger.info(f"Cached PDF: {cache_key}")
        return True
    except Exception as e:
        logger.warning(f"Failed to cache PDF: {str(e)}")
        return False


def render_template(template_name: str, data: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Render a Jinja2 template with the provided data.
    
    Args:
        template_name: The name of the template file
        data: The data dictionary to render with
        
    Returns:
        Tuple of (success, html_content_or_error_message)
    """
    try:
        logger.info(f"Rendering template: {template_name}")
        template = jinja_env.get_template(template_name)
        html_content = template.render(**data)
        logger.info(f"Successfully rendered template: {template_name}")
        return True, html_content
    except TemplateNotFound as e:
        error_msg = f"Template not found: {str(e)}"
        logger.error(error_msg)
        return False, error_msg
    except TemplateSyntaxError as e:
        error_msg = f"Template syntax error: {str(e)}"
        logger.error(error_msg)
        return False, error_msg
    except Exception as e:
        error_msg = f"Template rendering error: {str(e)}"
        logger.error(error_msg)
        return False, error_msg


def generate_pdf_from_html(html_content: str, filename: Optional[str] = None) -> Tuple[bool, bytes | str]:
    """
    Generate a PDF from HTML content using WeasyPrint.
    
    Args:
        html_content: The HTML content to convert
        filename: Optional filename for the output PDF
        
    Returns:
        Tuple of (success, pdf_bytes_or_error_message)
    """
    try:
        logger.info("Starting PDF generation from HTML")
        
        pdf_document = weasyprint.HTML(string=html_content)
        pdf_bytes = pdf_document.write_pdf()
        
        if filename:
            output_path = os.path.join(OUTPUT_DIR, filename)
            with open(output_path, 'wb') as f:
                f.write(pdf_bytes)
            logger.info(f"PDF saved to: {output_path}")
        
        logger.info("Successfully generated PDF")
        return True, pdf_bytes
    except Exception as e:
        error_msg = f"PDF generation error: {str(e)}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        return False, error_msg


def require_json(f):
    """
    Decorator to ensure request has JSON content type.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not request.is_json:
            return jsonify({
                'success': False,
                'error': 'Content-Type must be application/json'
            }), 400
        return f(*args, **kwargs)
    return decorated_function


def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent directory traversal and invalid characters.
    
    Args:
        filename: The filename to sanitize
        
    Returns:
        A safe filename
    """
    invalid_chars = ['<', '>', ':', '"', '/', '\\', '|', '?', '*', '.']
    safe_name = filename
    for char in invalid_chars:
        safe_name = safe_name.replace(char, '_')
    return safe_name[:255]


@app.route('/health', methods=['GET'])
def health_check():
    """
    Health check endpoint to verify the API is running.
    """
    return jsonify({
        'status': 'healthy',
        'service': 'pdf-generation-api',
        'timestamp': datetime.utcnow().isoformat()
    }), 200


@app.route('/templates', methods=['GET'])
def list_templates():
    """
    List all available templates.
    """
    try:
        templates = []
        if os.path.exists(TEMPLATES_DIR):
            for filename in os.listdir(TEMPLATES_DIR):
                if filename.endswith(('.html', '.xml', '.jinja2')):
                    filepath = os.path.join(TEMPLATES_DIR, filename)
                    file_size = os.path.getsize(filepath)
                    templates.append({
                        'name': filename,
                        'size': file_size,
                        'modified': datetime.fromtimestamp(os.path.getmtime(filepath)).isoformat()
                    })
        
        logger.info(f"Listed {len(templates)} templates")
        return jsonify({
            'success': True,
            'templates': templates,
            'count': len(templates)
        }), 200
    except Exception as e:
        error_msg = f"Error listing templates: {str(e)}"
        logger.error(error_msg)
        return jsonify({
            'success': False,
            'error': error_msg
        }), 500


@app.route('/generate', methods=['POST'])
@require_json
def generate_pdf():
    """
    Main endpoint to generate a PDF from a template and JSON data.
    
    Expected JSON payload:
    {
        "template": "template_name.html",
        "data": { ... },
        "use_cache": true,
        "filename": "output.pdf"
    }
    """
    try:
        request_data = request.get_json()
        
        if not request_data:
            return jsonify({
                'success': False,
                'error': 'Request body cannot be empty'
            }), 400
        
        template_name = request_data.get('template')
        data = request_data.get('data', {})
        use_cache = request_data.get('use_cache', True)
        filename = request_data.get('filename')
        
        if not template_name:
            return jsonify({
                'success': False,
                'error': 'Template name is required'
            }), 400
        
        is_valid, error_msg = validate_template_name(template_name)
        if not is_valid:
            return jsonify({
                'success': False,
                'error': error_msg
            }), 400
        
        is_valid, error_msg = validate_json_data(data)
        if not is_valid:
            return jsonify({
                'success': False,
                'error': error_msg
            }), 400
        
        cache_key = generate_cache_key(template_name, data)
        
        if use_cache:
            cached_pdf = get_cached_pdf(cache_key)
            if cached_pdf:
                return send_file(
                    BytesIO(cached_pdf),
                    mimetype='application/pdf',
                    as_attachment=True,
                    download_name=filename or f"{template_name.split('.')[0]}.pdf"
                )
        
        success, result = render_template(template_name, data)
        if not success:
            return jsonify({
                'success': False,
                'error': result
            }), 400
        
        html_content = result
        
        output_filename = None
        if filename:
            output_filename = sanitize_filename(filename)
        
        success, pdf_result = generate_pdf_from_html(html_content, output_filename)
        if not success:
            return jsonify({
                'success': False,
                'error': pdf_result
            }), 500
        
        pdf_bytes = pdf_result
        
        if use_cache:
            cache_pdf(cache_key, pdf_bytes)
        
        logger.info(f"Successfully generated PDF for template: {template_name}")
        
        return send_file(
            BytesIO(pdf_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=filename or f"{template_name.split('.')[0]}.pdf"
        )
    
    except Exception as e:
        error_msg = f"Unexpected error: {str(e)}"
        logger.error(error_msg)
        logger.error(traceback.format_exc())
        return jsonify({
            'success': False,
            'error': error_msg
        }), 500


@app.route('/generate-batch', methods=['POST'])
@require_json
def generate_batch_pdfs():
    """
    Generate multiple PDFs in a single request.
    
    Expected JSON payload:
    {
        "requests": [
            {
                "template": "template_name.html",
                "data": { ... },
                "filename": "output1.pdf"
            },
            ...
        ]
    }
    """
    try:
        request_data = request.get_json()
        
        if not request_data:
            return jsonify({
                'success': False,
                'error': 'Request body cannot be empty'
            }), 400
        
        requests_list = request_data.get('requests', [])
        
        if not isinstance(requests_list, list) or len(requests_list) == 0:
            return jsonify({
                'success': False,
                'error': 'Requests must be a non-empty list'
            }), 400
        
        if len(requests_list) > 100:
            return jsonify({
                'success': False,
                'error': 'Maximum 100 requests per batch'
            }), 400
        
        results = []
        
        for idx, req in enumerate(requests_list):
            try:
                template_name = req.get('template')
                data = req.get('data', {})
                filename = req.get('filename')
                
                if not template_name:
                    results.append({
                        'index': idx,
                        'success': False,
                        'error': 'Template name is required'
                    })
                    continue
                
                is_valid, error_msg = validate_template_name(template_name)
                if not is_valid:
                    results.append({
                        'index': idx,
                        'success': False,
                        'error': error_msg
                    })
                    continue
                
                is_valid, error_msg = validate_json_data(data)
                if not is_valid:
                    results.append({
                        'index': idx,
                        'success': False,
                        'error': error_msg
                    })