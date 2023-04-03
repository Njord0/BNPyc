### BNPyc

## Binary ninja plugin for python bytecode (pyc) disassembly and analysis.

Python versions from 3.0 to 3.10 are supported!
> IL Lifting is not implemented yet, as a result ILs are not available.

## Installation

Clone this repository into BinaryNinja plugin folder and install requirements with pip : 

```shell
cd BNPyc/
python3 -m pip install -r requirements.txt
```

## Usage

Choose any `.pyc` file and open it with binary ninja.

![](images/pycview1.png)
Example with a simple for loop

## Features

- Recursive functions detections and disassembly
- Branchs annotations
- Comparisons annotations
- Inlined `co_consts` `co_names` `co_varnames`
- Objects mapping
