import setuptools
from pathlib import Path


CURRENT_FOLDER = Path(__file__).parent
README_PATH = CURRENT_FOLDER / 'README.md'


setuptools.setup(
    name = "peor",
    version = "1.0.0",
    author = "Ariel Tubul",
    packages = setuptools.find_packages(),
    long_description=README_PATH.read_text(),
    install_requires = ['pefile'],
    long_description_content_type='text/markdown',
    url = "https://github.com/mon231/peor/",
    description = "PortableExecutable shellcodifier",
    entry_points = {'console_scripts': ['peor=peor.__main__:main']}
)
