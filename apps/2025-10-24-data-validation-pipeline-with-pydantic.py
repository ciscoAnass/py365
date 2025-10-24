import sys
import csv
import json
import logging
from typing import List, Optional, Union
from pydantic import BaseModel, Field, ValidationError, validator
from datetime import datetime, date

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class PersonModel(BaseModel):
    id: int = Field(..., gt=0)
    name: str = Field(..., min_length=2, max_length=100)
    email: str
    age: int = Field(..., ge=18, le=120)
    registration_date: Union[date, datetime]
    active: bool = True
    salary: Optional[float] = Field(default=None, ge=0)

    @validator('email')
    def validate_email(cls, v):
        if '@' not in v or '.' not in v:
            raise ValueError('Invalid email format')
        return v.lower()

    @validator('registration_date', pre=True)
    def parse_registration_date(cls, v):
        if isinstance(v, str):
            try:
                return datetime.fromisoformat(v)
            except ValueError:
                try:
                    return datetime.strptime(v, '%Y-%m-%d')
                except ValueError:
                    raise ValueError('Invalid date format')
        return v

class DataValidationPipeline:
    def __init__(self, input_file: str, output_valid: str, output_invalid: str):
        self.input_file = input_file
        self.output_valid = output_valid
        self.output_invalid = output_invalid
        self.valid_records: List[PersonModel] = []
        self.invalid_records: List[dict] = []

    def _detect_file_type(self) -> str:
        if self.input_file.endswith('.csv'):
            return 'csv'
        elif self.input_file.endswith('.json'):
            return 'json'
        else:
            raise ValueError(f"Unsupported file type: {self.input_file}")

    def _read_csv(self) -> List[dict]:
        with open(self.input_file, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)
            return list(reader)

    def _read_json(self) -> List[dict]:
        with open(self.input_file, 'r', encoding='utf-8') as f:
            return json.load(f)

    def validate_data(self):
        file_type = self._detect_file_type()
        
        records = self._read_csv() if file_type == 'csv' else self._read_json()
        
        for record in records:
            try:
                validated_record = PersonModel(**record)
                self.valid_records.append(validated_record)
                logger.info(f"Valid record: {validated_record}")
            except ValidationError as e:
                record['validation_errors'] = str(e)
                self.invalid_records.append(record)
                logger.warning(f"Invalid record: {record}")

    def write_results(self):
        with open(self.output_valid, 'w', encoding='utf-8') as valid_file:
            json.dump([record.dict() for record in self.valid_records], valid_file, indent=2, default=str)

        with open(self.output_invalid, 'w', encoding='utf-8') as invalid_file:
            json.dump(self.invalid_records, invalid_file, indent=2)

        logger.info(f"Total valid records: {len(self.valid_records)}")
        logger.info(f"Total invalid records: {len(self.invalid_records)}")

def main():
    if len(sys.argv) != 4:
        print("Usage: python script.py <input_file> <valid_output> <invalid_output>")
        sys.exit(1)

    input_file = sys.argv[1]
    output_valid = sys.argv[2]
    output_invalid = sys.argv[3]

    pipeline = DataValidationPipeline(input_file, output_valid, output_invalid)
    pipeline.validate_data()
    pipeline.write_results()

if __name__ == "__main__":
    main()