# PE-DeepLearn

Deep learning for PE file analysis: headers, imports, sections.

## Overview

- Analyze PE file structure
- Extract features from headers, imports, sections
- Multiple DL approaches: CNN, RNN, Transformer

## Features

- Header analysis (DOS, PE, optional headers)
- Import/Export table analysis
- Section characteristics
- Resource analysis

## Quick Start

```bash
python scripts/analyze_pe.py --file sample.exe
python scripts/train.py --model transformer
```
