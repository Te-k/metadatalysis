# Metadatalysis

Simple python tool to extract and analyze metadata in a set of documents. Relies on exiftool to get metadata, allows to extract metadata in images for pdf, docx, pptx and xlsx. Tested on Linux only.

## Usage

```
usage: metadatalysis.py [-h] [--output OUTPUT] [--level {all,useful,sensitive}] [--display {all,useful,file,none}] [--children]
                        [--summary SUMMARY]
                        PATH

Process some files to extract metadata

positional arguments:
  PATH                  Folder or file path

options:
  -h, --help            show this help message and exit
  --output, -o OUTPUT   Store data in output file
  --level, -l {all,useful,sensitive}
                        How much metadata do you want?
  --display, -d {all,useful,file,none}
                        What do you want displayed?
  --children, -c        Tries to parse metadata of files within files
  --summary, -s SUMMARY
                        Generate and dumps a summary of the data in a given file
```

Example: `python metadatanlysis.py FOLDER -c -l all -d file -o metadata.csv -o metadata.json`

## Issues

If you encounter the issue of having too many files opened, just `ulimit -Sn 10000`

## Similar Projects

* [MetaDetective](https://github.com/franckferman/MetaDetective) does a similar thing
* [metagoofil](https://github.com/opsdisk/metagoofil) allows to download files to check for metadata
* [mat2](https://github.com/tpet/mat2/tree/master) allows to remove sensitive metadata from files

## License

Published under [MIT](LICENSE) license.


