import json
import re
import csv
import sys
from typing import Dict, List, Tuple, Any

class PIIDetectorRedactor:
    def __init__(self):
        # Regex patterns for standalone PII
        self.patterns = {
            'phone': re.compile(r'\b\d{10}\b'),
            'aadhar': re.compile(r'\b\d{4}\s?\d{4}\s?\d{4}\b'),
            'passport': re.compile(r'\b[A-Z]{1,2}\d{6,7}\b'),
            'upi': re.compile(r'\b[\w.-]+@(upi|ybl|axl|okbiz|paytm)\b', re.IGNORECASE)
        }
        
        # Combinatorial PII indicators
        self.combinatorial_indicators = {
            'name': ['name', 'first_name', 'last_name'],
            'email': ['email'],
            'address': ['address', 'street', 'city', 'pin_code', 'state', 'state_code'],
            'device_ip': ['device_id', 'ip_address']
        }

        # Common non-PII patterns to avoid false positives
        self.non_pii_patterns = {
            'transaction_id': re.compile(r'\b(TXN|ORD|INV)-?\d+\b', re.IGNORECASE),
            'product_id': re.compile(r'\b(PROD|ITEM)-?\d+\b', re.IGNORECASE),
            'order_id': re.compile(r'\b(ORD|BK)-?\d+\b', re.IGNORECASE)
        }

    def is_likely_non_pii(self, value: str) -> bool:
        """Check if value matches common non-PII patterns"""
        if not isinstance(value, str):
            return False
            
        for pattern in self.non_pii_patterns.values():
            if pattern.search(value):
                return True
        return False

    def detect_standalone_pii(self, value: str) -> List[str]:
        """Detect standalone PII in a string value"""
        detected = []
        
        if not isinstance(value, str) or self.is_likely_non_pii(value):
            return detected
            
        # Check for phone numbers
        phone_matches = self.patterns['phone'].findall(value)
        if phone_matches:
            for match in phone_matches:
                # Additional validation to avoid false positives
                if not match.startswith(('000', '999')):  # Avoid test numbers
                    detected.append('phone')
            
        # Check for Aadhar numbers
        if self.patterns['aadhar'].search(value):
            detected.append('aadhar')
            
        # Check for passport numbers
        if self.patterns['passport'].search(value):
            detected.append('passport')
            
        # Check for UPI IDs
        if self.patterns['upi'].search(value):
            detected.append('upi')
            
        return detected

    def detect_combinatorial_pii(self, record: Dict[str, Any]) -> bool:
        """Check if combinatorial PII exists in the record"""
        found_categories = set()
        
        for category, keys in self.combinatorial_indicators.items():
            for key in keys:
                if (key in record and record[key] and 
                    str(record[key]).strip() and not self.is_likely_non_pii(str(record[key]))):
                    found_categories.add(category)
                    break
        
        # Need at least 2 combinatorial PII categories to be considered PII
        return len(found_categories) >= 2

    def redact_value(self, value: str, pii_type: str) -> str:
        """Redact PII values based on type"""
        if not isinstance(value, str):
            return value
            
        if pii_type == 'phone':
            return re.sub(r'(\d{2})\d{6}(\d{2})', r'\1XXXXXX\2', value)
        elif pii_type == 'aadhar':
            return re.sub(r'(\d{4})\s?\d{4}\s?(\d{4})', r'\1 XXXX XXXX \2', value)
        elif pii_type == 'passport':
            return re.sub(r'([A-Z]{1,2})(\d{6,7})', r'\1XXXXXX', value)
        elif pii_type == 'upi':
            return re.sub(r'([\w.-]+)@([\w.-]+)', r'XXXXX@\2', value)
        elif pii_type == 'name':
            # For names, keep first and last initial, redact the rest
            parts = value.split()
            if len(parts) >= 2:
                return f"{parts[0][0]}{'X'*(len(parts[0])-1)} {parts[-1][0]}{'X'*(len(parts[-1])-1)}"
            else:
                return f"{value[0]}{'X'*(len(value)-1)}"
        elif pii_type == 'email':
            # Redact username part of email
            return re.sub(r'([^@]+)@([^@]+\.[^@]+)', r'XXXXX@\2', value)
        else:
            # Generic redaction for other PII types
            return '[REDACTED_PII]'

    def process_record(self, record: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
        """Process a single record to detect and redact PII"""
        redacted_record = record.copy()
        has_standalone_pii = False
        has_combinatorial_pii = False
        
        # First pass: detect and redact standalone PII
        for key, value in record.items():
            if value and isinstance(value, str):
                pii_types = self.detect_standalone_pii(value)
                if pii_types:
                    has_standalone_pii = True
                    # Redact all detected PII types in this value
                    for pii_type in pii_types:
                        redacted_record[key] = self.redact_value(redacted_record[key], pii_type)
        
        # Second pass: detect combinatorial PII
        has_combinatorial_pii = self.detect_combinatorial_pii(record)
        
        # If combinatorial PII found, redact all combinatorial fields
        if has_combinatorial_pii:
            for category, keys in self.combinatorial_indicators.items():
                for key in keys:
                    if key in redacted_record and redacted_record[key]:
                        if category == 'name':
                            redacted_record[key] = self.redact_value(redacted_record[key], 'name')
                        elif category == 'email':
                            redacted_record[key] = self.redact_value(redacted_record[key], 'email')
                        else:
                            redacted_record[key] = self.redact_value(redacted_record[key], 'generic')
        
        # Determine if record contains any PII
        has_pii = has_standalone_pii or has_combinatorial_pii
        
        return redacted_record, has_pii

    def process_csv(self, input_file: str, output_file: str):
        """Process the entire CSV file"""
        with open(input_file, 'r', newline='', encoding='utf-8') as infile, \
             open(output_file, 'w', newline='', encoding='utf-8') as outfile:
            
            reader = csv.DictReader(infile)
            fieldnames = ['record_id', 'redacted_data_json', 'is_pii']
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for row in reader:
                try:
                    # Parse the JSON data
                    data_json = json.loads(row['Data_json'])
                    record_id = row['record_id']
                    
                    # Process the record
                    redacted_data, is_pii = self.process_record(data_json)
                    
                    # Write the result
                    writer.writerow({
                        'record_id': record_id,
                        'redacted_data_json': json.dumps(redacted_data),
                        'is_pii': is_pii
                    })
                    
                except json.JSONDecodeError:
                    # Handle invalid JSON
                    writer.writerow({
                        'record_id': row['record_id'],
                        'redacted_data_json': row['Data_json'],
                        'is_pii': False
                    })
                except Exception as e:
                    print(f"Error processing record {row.get('record_id', 'unknown')}: {e}")
                    writer.writerow({
                        'record_id': row.get('record_id', 'unknown'),
                        'redacted_data_json': row.get('Data_json', '{}'),
                        'is_pii': False
                    })

def main():
    if len(sys.argv) != 2:
        print("Usage: python detector_full_candidate_name.py input.csv")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = "redacted_output_candidate_full_name.csv"
    
    detector = PIIDetectorRedactor()
    detector.process_csv(input_file, output_file)
    print(f"Processing complete. Output saved to {output_file}")

if __name__ == "__main__":
    main()