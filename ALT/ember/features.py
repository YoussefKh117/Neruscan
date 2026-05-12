#!/usr/bin/python
''' Extracts some basic features from PE files. '''

import re
import lief
import hashlib
import numpy as np
import os
import json
from sklearn.feature_extraction import FeatureHasher

LIEF_MAJOR, LIEF_MINOR, _ = lief.__version__.split('.')
LIEF_EXPORT_OBJECT = int(LIEF_MAJOR) > 0 or ( int(LIEF_MAJOR)==0 and int(LIEF_MINOR) >= 10 )
LIEF_HAS_SIGNATURE = int(LIEF_MAJOR) > 0 or (int(LIEF_MAJOR) == 0 and int(LIEF_MINOR) >= 11)


class FeatureType(object):
    ''' Base class from which each feature type may inherit '''
    name = ''
    dim = 0

    def __repr__(self):
        return '{}({})'.format(self.name, self.dim)

    def raw_features(self, bytez, lief_binary):
        raise (NotImplementedError)

    def process_raw_features(self, raw_obj):
        raise (NotImplementedError)

    def feature_vector(self, bytez, lief_binary):
        return self.process_raw_features(self.raw_features(bytez, lief_binary))


class ByteHistogram(FeatureType):
    ''' Byte histogram over the entire binary file '''
    name = 'histogram'
    dim = 256

    def __init__(self):
        super(FeatureType, self).__init__()

    def raw_features(self, bytez, lief_binary):
        counts = np.bincount(np.frombuffer(bytez, dtype=np.uint8), minlength=256)
        return counts.tolist()

    def process_raw_features(self, raw_obj):
        counts = np.array(raw_obj, dtype=np.float32)
        sum_counts = counts.sum()
        normalized = counts / (sum_counts if sum_counts > 0 else 1.0)
        return normalized


class ByteEntropyHistogram(FeatureType):
    ''' 2d byte/entropy histogram '''
    name = 'byteentropy'
    dim = 256

    def __init__(self, step=1024, window=2048):
        super(FeatureType, self).__init__()
        self.window = window
        self.step = step

    def _entropy_bin_counts(self, block):
        c = np.bincount(block >> 4, minlength=16)
        p = c.astype(np.float32) / self.window
        wh = np.where(c)[0]
        H = np.sum(-p[wh] * np.log2(p[wh])) * 2
        Hbin = int(H * 2)
        if Hbin == 16:
            Hbin = 15
        return Hbin, c

    def raw_features(self, bytez, lief_binary):
        # FIX 1: dtype=int (compatible with NumPy 2.x)
        output = np.zeros((16, 16), dtype=int)
        a = np.frombuffer(bytez, dtype=np.uint8)
        if a.shape[0] < self.window:
            Hbin, c = self._entropy_bin_counts(a)
            output[Hbin, :] += c
        else:
            shape = a.shape[:-1] + (a.shape[-1] - self.window + 1, self.window)
            strides = a.strides + (a.strides[-1],)
            blocks = np.lib.stride_tricks.as_strided(a, shape=shape, strides=strides)[::self.step, :]
            for block in blocks:
                Hbin, c = self._entropy_bin_counts(block)
                output[Hbin, :] += c
        return output.flatten().tolist()

    def process_raw_features(self, raw_obj):
        counts = np.array(raw_obj, dtype=np.float32)
        sum_counts = counts.sum()
        normalized = counts / (sum_counts if sum_counts > 0 else 1.0)
        return normalized


class SectionInfo(FeatureType):
    ''' Information about section names, sizes and entropy '''
    name = 'section'
    dim = 255

    def __init__(self):
        super(FeatureType, self).__init__()

    @staticmethod
    def _properties(s):
        return [str(c).split('.')[-1] for c in s.characteristics_lists]

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return {"entry": "", "sections": []}
        try:
            if int(LIEF_MAJOR) > 0 or (int(LIEF_MAJOR) == 0 and int(LIEF_MINOR) >= 12):
                section = lief_binary.section_from_rva(lief_binary.entrypoint - lief_binary.imagebase)
                entry_section = section.name if section else ""
            else:
                entry_section = lief_binary.section_from_offset(lief_binary.entrypoint).name
        except Exception:
            entry_section = ""
            for s in lief_binary.sections:
                if lief.PE.SECTION_CHARACTERISTICS.MEM_EXECUTE in s.characteristics_lists:
                    entry_section = s.name
                    break

        raw_obj = {"entry": entry_section}
        raw_obj["sections"] = [{
            'name': s.name, 'size': s.size, 'entropy': s.entropy,
            'vsize': s.virtual_size, 'props': self._properties(s)
        } for s in lief_binary.sections]
        return raw_obj

    def process_raw_features(self, raw_obj):
        sections = raw_obj['sections']
        general = [
            len(sections),
            sum(1 for s in sections if s['size'] == 0),
            sum(1 for s in sections if s['name'] == ""),
            sum(1 for s in sections if 'MEM_READ' in s['props'] and 'MEM_EXECUTE' in s['props']),
            sum(1 for s in sections if 'MEM_WRITE' in s['props'])
        ]
        section_sizes = [(s['name'], s['size']) for s in sections]
        section_sizes_hashed = FeatureHasher(50, input_type="pair").transform([section_sizes]).toarray()[0]
        section_entropy = [(s['name'], s['entropy']) for s in sections]
        section_entropy_hashed = FeatureHasher(50, input_type="pair").transform([section_entropy]).toarray()[0]
        section_vsize = [(s['name'], s['vsize']) for s in sections]
        section_vsize_hashed = FeatureHasher(50, input_type="pair").transform([section_vsize]).toarray()[0]
        
        # FIX 2: Double brackets [[ ]] for single string FeatureHasher
        entry_name_hashed = FeatureHasher(50, input_type="string").transform([[raw_obj['entry']]]).toarray()[0]
        
        characteristics = [p for s in sections for p in s['props'] if s['name'] == raw_obj['entry']]
        characteristics_hashed = FeatureHasher(50, input_type="string").transform([characteristics]).toarray()[0]

        return np.hstack([
            general, section_sizes_hashed, section_entropy_hashed, section_vsize_hashed, entry_name_hashed,
            characteristics_hashed
        ]).astype(np.float32)


class ImportsInfo(FeatureType):
    ''' Information about imported libraries '''
    name = 'imports'
    dim = 1280

    def __init__(self):
        super(FeatureType, self).__init__()

    def raw_features(self, bytez, lief_binary):
        imports = {}
        if lief_binary is None: return imports
        for lib in lief_binary.imports:
            if lib.name not in imports: imports[lib.name] = []
            for entry in lib.entries:
                if entry.is_ordinal: imports[lib.name].append("ordinal" + str(entry.ordinal))
                else: imports[lib.name].append(entry.name[:10000])
        return imports

    def process_raw_features(self, raw_obj):
        libraries = list(set([l.lower() for l in raw_obj.keys()]))
        libraries_hashed = FeatureHasher(256, input_type="string").transform([libraries]).toarray()[0]
        imports = [lib.lower() + ':' + e for lib, elist in raw_obj.items() for e in elist]
        imports_hashed = FeatureHasher(1024, input_type="string").transform([imports]).toarray()[0]
        return np.hstack([libraries_hashed, imports_hashed]).astype(np.float32)


class ExportsInfo(FeatureType):
    ''' Information about exported functions '''
    name = 'exports'
    dim = 128

    def __init__(self):
        super(FeatureType, self).__init__()

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None: return []
        if LIEF_EXPORT_OBJECT:
            clipped_exports = [export.name[:10000] for export in lief_binary.exported_functions]
        else:
            clipped_exports = [export[:10000] for export in lief_binary.exported_functions]
        return clipped_exports

    def process_raw_features(self, raw_obj):
        exports_hashed = FeatureHasher(128, input_type="string").transform([raw_obj]).toarray()[0]
        return exports_hashed.astype(np.float32)


class GeneralFileInfo(FeatureType):
    ''' General information about the file '''
    name = 'general'
    dim = 10

    def __init__(self):
        super(FeatureType, self).__init__()

    def raw_features(self, bytez, lief_binary):
        if lief_binary is None:
            return {'size': len(bytez), 'vsize': 0, 'has_debug': 0, 'exports': 0, 'imports': 0,
                    'has_relocations': 0, 'has_resources': 0, 'has_signature': 0, 'has_tls': 0, 'symbols': 0}
        return {
            'size': len(bytez), 'vsize': lief_binary.virtual_size, 'has_debug': int(lief_binary.has_debug),
            'exports': len(lief_binary.exported_functions), 'imports': len(lief_binary.imported_functions),
            'has_relocations': int(lief_binary.has_relocations), 'has_resources': int(lief_binary.has_resources),
            'has_signature': int(lief_binary.has_signatures) if LIEF_HAS_SIGNATURE else int(lief_binary.has_signature),
            'has_tls': int(lief_binary.has_tls), 'symbols': len(lief_binary.symbols),
        }

    def process_raw_features(self, raw_obj):
        return np.asarray([
            raw_obj['size'], raw_obj['vsize'], raw_obj['has_debug'], raw_obj['exports'], raw_obj['imports'],
            raw_obj['has_relocations'], raw_obj['has_resources'], raw_obj['has_signature'], raw_obj['has_tls'],
            raw_obj['symbols']
        ], dtype=np.float32)


class HeaderFileInfo(FeatureType):
    ''' Information extracted from PE header '''
    name = 'header'
    dim = 62

    def __init__(self):
        super(FeatureType, self).__init__()

    def raw_features(self, bytez, lief_binary):
        raw_obj = {'coff': {'timestamp': 0, 'machine': "", 'characteristics': []},
                   'optional': {'subsystem': "", 'dll_characteristics': [], 'magic': "",
                                'major_image_version': 0, 'minor_image_version': 0,
                                'major_linker_version': 0, 'minor_linker_version': 0,
                                'major_operating_system_version': 0, 'minor_operating_system_version': 0,
                                'major_subsystem_version': 0, 'minor_subsystem_version': 0,
                                'sizeof_code': 0, 'sizeof_headers': 0, 'sizeof_heap_commit': 0}}
        if lief_binary is None: return raw_obj
        raw_obj['coff']['timestamp'] = lief_binary.header.time_date_stamps
        raw_obj['coff']['machine'] = str(lief_binary.header.machine).split('.')[-1]
        raw_obj['coff']['characteristics'] = [str(c).split('.')[-1] for c in lief_binary.header.characteristics_list]
        raw_obj['optional']['subsystem'] = str(lief_binary.optional_header.subsystem).split('.')[-1]
        raw_obj['optional']['dll_characteristics'] = [str(c).split('.')[-1] for c in lief_binary.optional_header.dll_characteristics_lists]
        raw_obj['optional']['magic'] = str(lief_binary.optional_header.magic).split('.')[-1]
        raw_obj['optional']['major_image_version'] = lief_binary.optional_header.major_image_version
        raw_obj['optional']['minor_image_version'] = lief_binary.optional_header.minor_image_version
        raw_obj['optional']['major_linker_version'] = lief_binary.optional_header.major_linker_version
        raw_obj['optional']['minor_linker_version'] = lief_binary.optional_header.minor_linker_version
        raw_obj['optional']['major_operating_system_version'] = lief_binary.optional_header.major_operating_system_version
        raw_obj['optional']['minor_operating_system_version'] = lief_binary.optional_header.minor_operating_system_version
        raw_obj['optional']['major_subsystem_version'] = lief_binary.optional_header.major_subsystem_version
        raw_obj['optional']['minor_subsystem_version'] = lief_binary.optional_header.minor_subsystem_version
        raw_obj['optional']['sizeof_code'] = lief_binary.optional_header.sizeof_code
        raw_obj['optional']['sizeof_headers'] = lief_binary.optional_header.sizeof_headers
        raw_obj['optional']['sizeof_heap_commit'] = lief_binary.optional_header.sizeof_heap_commit
        return raw_obj

    def process_raw_features(self, raw_obj):
        # FIX 3: Double brackets for single string transforms
        return np.hstack([
            raw_obj['coff']['timestamp'],
            FeatureHasher(10, input_type="string").transform([[raw_obj['coff']['machine']]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([raw_obj['coff']['characteristics']]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([[raw_obj['optional']['subsystem']]]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([raw_obj['optional']['dll_characteristics']]).toarray()[0],
            FeatureHasher(10, input_type="string").transform([[raw_obj['optional']['magic']]]).toarray()[0],
            raw_obj['optional']['major_image_version'], raw_obj['optional']['minor_image_version'],
            raw_obj['optional']['major_linker_version'], raw_obj['optional']['minor_linker_version'],
            raw_obj['optional']['major_operating_system_version'], raw_obj['optional']['minor_operating_system_version'],
            raw_obj['optional']['major_subsystem_version'], raw_obj['optional']['minor_subsystem_version'],
            raw_obj['optional']['sizeof_code'], raw_obj['optional']['sizeof_headers'], raw_obj['optional']['sizeof_heap_commit'],
        ]).astype(np.float32)


class StringExtractor(FeatureType):
    ''' Extracts strings from raw byte stream '''
    name = 'strings'
    dim = 104

    def __init__(self):
        super(FeatureType, self).__init__()
        self._allstrings = re.compile(b'[\x20-\x7f]{5,}')
        self._paths = re.compile(b'c:\\\\', re.IGNORECASE)
        self._urls = re.compile(b'https?://', re.IGNORECASE)
        self._registry = re.compile(b'HKEY_')
        self._mz = re.compile(b'MZ')

    def raw_features(self, bytez, lief_binary):
        allstrings = self._allstrings.findall(bytez)
        if allstrings:
            string_lengths = [len(s) for s in allstrings]
            avlength = sum(string_lengths) / len(string_lengths)
            as_shifted_string = [b - ord(b'\x20') for b in b''.join(allstrings)]
            c = np.bincount(as_shifted_string, minlength=96)
            csum = c.sum()
            p = c.astype(np.float32) / (csum if csum > 0 else 1.0)
            wh = np.where(c)[0]
            H = np.sum(-p[wh] * np.log2(p[wh])) if len(wh) > 0 else 0
        else:
            avlength, H, csum = 0, 0, 0
            c = np.zeros((96,), dtype=np.float32)
        return {'numstrings': len(allstrings), 'avlength': avlength, 'printabledist': c.tolist(),
                'printables': int(csum), 'entropy': float(H), 'paths': len(self._paths.findall(bytez)),
                'urls': len(self._urls.findall(bytez)), 'registry': len(self._registry.findall(bytez)),
                'MZ': len(self._mz.findall(bytez))}

    def process_raw_features(self, raw_obj):
        hist_divisor = float(raw_obj['printables']) if raw_obj['printables'] > 0 else 1.0
        return np.hstack([
            raw_obj['numstrings'], raw_obj['avlength'], raw_obj['printables'],
            np.asarray(raw_obj['printabledist']) / hist_divisor, raw_obj['entropy'], 
            raw_obj['paths'], raw_obj['urls'], raw_obj['registry'], raw_obj['MZ']
        ]).astype(np.float32)


class DataDirectories(FeatureType):
    ''' Extracts data directory info '''
    name = 'datadirectories'
    dim = 30

    def __init__(self):
        super(FeatureType, self).__init__()
        self._name_order = ["EXPORT_TABLE", "IMPORT_TABLE", "RESOURCE_TABLE", "EXCEPTION_TABLE", "CERTIFICATE_TABLE",
                            "BASE_RELOCATION_TABLE", "DEBUG", "ARCHITECTURE", "GLOBAL_PTR", "TLS_TABLE", "LOAD_CONFIG_TABLE",
                            "BOUND_IMPORT", "IAT", "DELAY_IMPORT_DESCRIPTOR", "CLR_RUNTIME_HEADER"]

    def raw_features(self, bytez, lief_binary):
        output = []
        if lief_binary is None: return output
        for dd in lief_binary.data_directories:
            output.append({"name": str(dd.type).replace("DATA_DIRECTORY.", ""), "size": dd.size, "virtual_address": dd.rva})
        return output

    def process_raw_features(self, raw_obj):
        features = np.zeros(30, dtype=np.float32)
        for i in range(min(len(self._name_order), len(raw_obj))):
            features[2 * i] = raw_obj[i]["size"]
            features[2 * i + 1] = raw_obj[i]["virtual_address"]
        return features


class PEFeatureExtractor(object):
    ''' Final extractor class '''
    def __init__(self, feature_version=2, print_feature_warning=True, features_file=''):
        self.features = []
        features_pool = {'ByteHistogram': ByteHistogram(), 'ByteEntropyHistogram': ByteEntropyHistogram(),
                         'StringExtractor': StringExtractor(), 'GeneralFileInfo': GeneralFileInfo(),
                         'HeaderFileInfo': HeaderFileInfo(), 'SectionInfo': SectionInfo(),
                         'ImportsInfo': ImportsInfo(), 'ExportsInfo': ExportsInfo()}
        if os.path.exists(features_file):
            with open(features_file, encoding='utf8') as f:
                x = json.load(f)
                self.features = [features_pool[f] for f in x['features'] if f in features_pool]
        else:
            self.features = list(features_pool.values())
        if feature_version == 2:
            self.features.append(DataDirectories())
        self.dim = sum([fe.dim for fe in self.features])

    def raw_features(self, bytez):
        # FIX 4: Modern LIEF compatibility for error handling
        lief_errors = (RuntimeError, Exception)
        try:
            lief_binary = lief.PE.parse(bytearray(bytez))
        except lief_errors:
            lief_binary = None
        except Exception:
            raise
        features = {"sha256": hashlib.sha256(bytez).hexdigest()}
        features.update({fe.name: fe.raw_features(bytez, lief_binary) for fe in self.features})
        return features

    def process_raw_features(self, raw_obj):
        return np.hstack([fe.process_raw_features(raw_obj[fe.name]) for fe in self.features]).astype(np.float32)

    def feature_vector(self, bytez):
        return self.process_raw_features(self.raw_features(bytez))