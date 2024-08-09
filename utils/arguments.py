import argparse
from typing import Protocol
import fileValidator

## create file validators
def validateFiles(file:str):
    if not fileValidator.areFilesExists([fileValidator.getAbsolutePath(file)]):
        raise argparse.ArgumentTypeError(f"The file named {file} doesn't exist")
    return file

# def validatePath(path)
def validateDirectory(directory:str):
    if not fileValidator.areDirectoriesExists([fileValidator.getAbsolutePath(directory)]):
        raise argparse.ArgumentTypeError(f"The output directory named {directory} doesn't exist")
    return directory

## create the parser
parser = argparse.ArgumentParser(
    prog="lktd-enc", description="This is the program for file encryption and decryption")

## add arguments to the parser

# add optional arguments
group = parser.add_mutually_exclusive_group(required=True)
group.add_argument("-d","--decrypt",action="store_true",help="Decrypt the given files")
group.add_argument("-e","--encrypt",action="store_true",help="Encrypt the given files")
parser.add_argument("-g","--gui",action="store_true",help="Launch the graphical user interface (GUI)")
parser.add_argument("-o","--output",help="Specify the output directory",type=validateDirectory, metavar="<output directory path>")
parser.add_argument("-p","--password",help="Specify the password", type=str, metavar="<password>")
parser.add_argument("-z","--zip",action="store_true",help="Specify the input files are zip files or not")
parser.add_argument("--zipFileName",help="Specify the output zip file name (default is output.zip)",metavar="<zip file name>.zip", default="output.zip")

# add positional arguments
parser.add_argument("files",nargs="+",help="List of files/zip files which need to encrypt/decrypt", type=validateFiles, metavar="[file1 file2 ...]")

class Arguments(Protocol):
    decrypt:bool
    encrypt:bool
    gui: bool
    output: str
    password:str
    zip:bool
    zipFileName:str
    files: list[str]

# parse the arguments
arguments:Arguments = parser.parse_args()