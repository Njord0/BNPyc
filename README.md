### BNPyc

<div align="center">
    Binary ninja plugin for python bytecode (pyc) disassembly and analysis.<br/><br/>
</div>

Python versions from 3.0 to 3.10 are supported!

## Installation

Clone this repository and install requirements :

<details>
    <summary>Linux</summary>
    
    git clone https://github.com/Njord0/BNPYC ~/.binaryninja/plugins/BNPyc
</details>

<details>
    <summary>Windows</summary>
    
    git clone https://github.com/Njord0/BNPYC %APPDATA%/Binary Ninja/plugins/BNPyc
</details>

<details>
    <summary>Darwin</summary>
    
    git clone https://github.com/Njord0/BNPYC ~/Library/Application Support/Binary Ninja/plugins/BNPyc
</details>
<br>
Then install requirements with pip :
```shell
cd BNPyc/
python3 -m pip install -r requirements.txt
```

## Usage

Choose any `.pyc` file and open it with binary ninja.

<img src="images/pycview1.png" alt="pycview1.png">
<p align="center">Example with a simple for loop</p>

## Features

- Recursive functions detections and disassembly
- Branchs annotations
- Comparisons annotations
- Inlined `co_consts` `co_names` `co_varnames`
- Objects mapping
