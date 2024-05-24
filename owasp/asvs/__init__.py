from owasp.asvs._asvs import *
from os import path

__all__ = [
    'chapter',
    'section',
    'requirement'
]

_module_dir = path.dirname(__file__)
_asvs_csv_filename = "OWASP Application Security Verification Standard 4.0.3-en.csv"
_asvs_csv_path = path.join(_module_dir, _asvs_csv_filename)

chapter, section, requirement = extract_data_from_asvs_csv(_asvs_csv_path)