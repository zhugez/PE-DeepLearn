"""
PE file analysis utilities.
"""

import pefile
import lief
from typing import Dict, List
import numpy as np


class PEAnalyzer:
    """Comprehensive PE file analyzer."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.pe = None

    def analyze(self) -> Dict:
        """Perform full analysis."""
        try:
            self.pe = pefile.PE(self.file_path)
            return {
                'headers': self._analyze_headers(),
                'sections': self._analyze_sections(),
                'imports': self._analyze_imports(),
                'exports': self._analyze_exports(),
                'resources': self._analyze_resources(),
            }
        except Exception as e:
            return {'error': str(e)}

    def _analyze_headers(self) -> Dict:
        """Analyze PE headers."""
        if not self.pe:
            return {}

        headers = {
            'machine': self.pe.FILE_HEADER.Machine,
            'timestamp': self.pe.FILE_HEADER.TimeDateStamp,
            'characteristics': self.pe.FILE_HEADER.Characteristics,
            'num_sections': self.pe.FILE_HEADER.NumberOfSections,
            'num_rva_and_sizes': self.pe.FILE_HEADER.NumberOfRvaAndSizes,
        }

        if hasattr(self.pe, 'OPTIONAL_HEADER'):
            headers['entry_point'] = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
            headers['image_base'] = self.pe.OPTIONAL_HEADER.ImageBase
            headers['section_alignment'] = self.pe.OPTIONAL_HEADER.SectionAlignment
            headers['file_alignment'] = self.pe.OPTIONAL_HEADER.FileAlignment
            headers['size_of_image'] = self.pe.OPTIONAL_HEADER.SizeOfImage
            headers['size_of_headers'] = self.pe.OPTIONAL_HEADER.SizeOfHeaders
            headers['subsystem'] = self.pe.OPTIONAL_HEADER.Subsystem

        return headers

    def _analyze_sections(self) -> List[Dict]:
        """Analyze PE sections."""
        if not self.pe:
            return []

        sections = []
        for section in self.pe.sections:
            try:
                name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                sections.append({
                    'name': name,
                    'virtual_address': section.VirtualAddress,
                    'virtual_size': section.Misc_VirtualSize,
                    'raw_size': section.SizeOfRawData,
                    'characteristics': section.Characteristics,
                    'entropy': self._calculate_entropy(section.get_data()),
                })
            except:
                continue
        return sections

    def _analyze_imports(self) -> List[Dict]:
        """Analyze import table."""
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            return []

        imports = []
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8', errors='ignore')
            functions = []
            for imp in entry.imports:
                if imp.name:
                    functions.append(imp.name.decode('utf-8', errors='ignore'))
            imports.append({
                'dll': dll_name,
                'functions': functions,
            })
        return imports

    def _analyze_exports(self) -> List[str]:
        """Analyze export table."""
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            return []

        exports = []
        for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode('utf-8', errors='ignore'))
        return exports

    def _analyze_resources(self) -> Dict:
        """Analyze resources."""
        if not self.pe or not hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            return {}

        resources = {
            'types': {},
            'count': 0,
        }

        if hasattr(self.pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in self.pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    resources['count'] += 1

        return resources

    def _calculate_entropy(self, data: bytes) -> float:
        """Calculate Shannon entropy."""
        if not data:
            return 0.0
        import math
        entropy = 0
        for x in range(256):
            p = data.count(bytes([x])) / len(data)
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy


class LIEFAnalyzer:
    """LIEF-based PE analyzer."""

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.binary = None

    def analyze(self) -> Dict:
        """Analyze using LIEF."""
        try:
            self.binary = lief.parse(self.file_path)
            return {
                'header': self._analyze_header(),
                'sections': self._analyze_sections(),
                'imports': self._analyze_imports(),
                'libraries': self._analyze_libraries(),
            }
        except Exception as e:
            return {'error': str(e)}

    def _analyze_header(self) -> Dict:
        if not self.binary:
            return {}
        return {
            'architecture': str(self.binary.header.architecture),
            'entrypoint': self.binary.header.entrypoint,
            'nb_sections': self.binary.header.nb_sections,
            'os': str(self.binary.header.os),
        }

    def _analyze_sections(self) -> List[Dict]:
        if not self.binary:
            return []
        return [{
            'name': s.name,
            'size': s.size,
            'virtual_size': s.virtual_size,
            'characteristics': str(s.characteristics),
        } for s in self.binary.sections]

    def _analyze_imports(self) -> List[Dict]:
        if not self.binary or not self.binary.imports:
            return []
        return [{
            'library': lib.name,
            'functions': [f.name for f in lib.entries],
        } for lib in self.binary.imports]

    def _analyze_libraries(self) -> List[str]:
        if not self.binary:
            return []
        return [lib.name for lib in self.binary.libraries]
