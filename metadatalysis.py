import subprocess
import os
import functools
import json
import argparse
import csv
import hashlib
from typing import Dict, Any, Optional


# List of system metadata, irrelevant here
META_ALLOWLIST = ["ExifToolVersion", "Directory", "ExifToolVersion", "FileAccessDate",
                    "FileInodeChangeDate", "FileModifyDate", "FileName",
                    "FilePermissions", "FileSize", "FileTypeExtension", "MIMEType",
                    "SourceFile", "BitsPerSample", "Linearized", "PageCount",
                    "ResolutionUnit", "APP14Flags0", "AudioBitsPerSample",
                    "AudioChannels", "AudioSampleRate", "AutoLateralCA",
                    "Balance", "CFAPattern", "CharCountWithSpaces",
                    "Characters", "ChromaticAdaptation"]

META_SENSITIVE = ["Creator", "Author", "Last Modified By", "Hyperlinks", "Creator Tool",
    "Producer", "Software", "Camera Model Name", "Image Description", "Make",
    "Camera ID", "GPS Position", "Formatted GPS Position", "Map Link"]


class File:
    def __init__(self, path: str):
        self._path = path
        self._all_metadata: Optional[Dict[str, Any]] = None

    @property
    def path(self) -> str:
        return self._path

    def exists(self) -> bool:
        """
        Check if file exists
        """
        return os.file.isfile(self.path)

    def sha256(self) -> str:
        """
        Return the SHA256 hash of the file
        """
        with open(self.path, "rb") as f:
            sha256 = hashlib.sha256()
            sha256.update(f.read())
            return sha256.hexdigest()

    def get_metadata(self) -> None:
        """
        Get metadata
        """
        try:
            out = subprocess.run([self._get_exiftool_path(), '-json', self.path],
                                    check=True, stdout=subprocess.PIPE).stdout
        except subprocess.CalledProcessError:
            # FIXME: improve error handling?
            print("Exiftool can't parse {}".format(self.path))
            self._all_metadata = {}
        else:
            self._all_metadata = json.loads(out.decode('utf-8'))[0]

    @property
    def all_metadata(self) -> Dict[str, Any]:
        if self._all_metadata is None:
            self.get_metadata()

        return self._all_metadata

    @property
    def metadata(self) -> Dict[str, Any]:
        if self._all_metadata is None:
            self.get_metadata()

        m = self._all_metadata
        for key in META_ALLOWLIST:
            m.pop(key, None)
        return m

    @property
    def sensitive_metadata(self) -> Dict[str, Any]:
        if self._metadata is None:
            self.get_metadata()
        meta = {}
        for key in META_SENSITIVE:
            if key in self._metadata:
                meta[key] = self._metadata[key]

        return meta

    @functools.lru_cache()
    def _get_exiftool_path(self) -> str:  # pragma: no cover
        """
        From MAT2
        https://github.com/tpet/mat2/blob/master/libmat2/exiftool.py
        """
        possible_pathes = {
            '/usr/bin/exiftool',              # debian/fedora
            '/usr/bin/vendor_perl/exiftool',  # archlinux
        }

        for possible_path in possible_pathes:
            if os.path.isfile(possible_path):
                if os.access(possible_path, os.X_OK):
                    return possible_path

        raise RuntimeError("Unable to find exiftool")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Process some files to extract metadata')
    parser.add_argument('PATH', help="Folder or file path")
    parser.add_argument('--output', '-o', help="Store data in output file")
    parser.add_argument('--format', '-f', default="csv", help="Output format")
    parser.add_argument('--sensitive', '-s', action="store_true", help="Only shows sensitive metadata")
    args = parser.parse_args()

    output_data = []
    if os.path.isfile(args.PATH):
        f = File(args.PATH)
        if args.sensitive:
            output_data.append({
                "path": args.PATH,
                "sha256": f.sha256(),
                "metadata": f.sensitive_metadata
            })
            print(json.dumps(f.sensitive_metadata, indent=4))
        else:
            output_data.append({
                "path": args.PATH,
                "sha256": f.sha256(),
                "metadata": f.metadata
            })
            print(json.dumps(f.metadata, indent=4))
    elif os.path.isdir(args.PATH):
        for root, dirs, files in os.walk(args.PATH):
            for file in files:
                fpath = os.path.join(root, file)
                f = File(fpath)
                if args.sensitive:
                    if f.sensitive_metadata != []:
                        print("{} : {}".format(fpath, json.dumps(f.sensitive_metadata, indent=4)))
                    output_data.append({
                        "path": fpath,
                        "sha256": f.sha256(),
                        "metadata": f.sensitive_metadata
                    })
                else:
                    print("{} : {}".format(fpath, json.dumps(f.metadata, indent=4)))
                    print(json.dumps(f.metadata, indent=4))
                    output_data.append({
                        "path": fpath,
                        "sha256": f.sha256(),
                        "metadata": f.metadata
                    })
    else:
        print("Invalid path, quitting")

    if args.output and len(output_data) > 0:
        if args.format == "json":
            with open(args.output, "w+") as f:
                f.write(json.dumps(output_data, indent=4))
        elif args.format == "csv":
            output_keys = []
            for entry in output_data:
                for k in entry["metadata"]:
                    output_keys.append(k)
            output_keys = sorted(list(set(output_keys)))
            with open(args.output, 'w+') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(["Path", "SHA256"] + output_keys)
                for entry in output_data:
                    line = [entry["path"], entry["sha256"]]
                    for k in output_keys:
                        if k in entry["metadata"]:
                            line.append(entry["metadata"][k])
                        else:
                            line.append("")
                    writer.writerow(line)
        print("Output written in {}".format(args.output))



