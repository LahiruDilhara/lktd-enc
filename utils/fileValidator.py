import os


def areFilesExists(absolutePaths: list[str]) -> bool:
    for filePath in absolutePaths:
        if not (os.path.exists(filePath) and os.path.isfile(filePath)):
            return False
    return True

def areDirectoriesExists(absolutePaths: list[str]) -> bool:
    for directoryPath in absolutePaths:
        if not (os.path.exists(directoryPath) and os.path.isdir(directoryPath)):
            return False
    return True


def getAbsolutePaths(paths: list[str]) -> list[str]:
    pathList: list[str] = []
    for filePath in paths:
        pathList.append(os.path.abspath(filePath))
    return pathList

def getAbsolutePath(path:list[str]) -> str:
    return os.path.abspath(path)