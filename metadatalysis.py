import subprocess
import os
import functools
import json
import argparse
import csv
import hashlib
import tempfile
import zipfile
import sys
import logging
from typing import Dict, Any, Optional, List, Self


# List of system metadata, irrelevant here
EXIFTOOL_META_ALLOWLIST = [
    "ExifToolVersion",
    "Directory",
    "ExifToolVersion",
    "FileAccessDate",
    "FileInodeChangeDate",
    "FileModifyDate",
    "FileName",
    "FileType",
    "SourceFile",
    "FilePermissions",
    "FileSize",
    "FileTypeExtension",
    "MIMEType",
]

META_ALLOWLIST = None

META_SENSITIVE = None

# Structured analysis of metadata
META_STRUCTURE = {
    "author": [
        "Artist",
        "Author",
        "By-line",
        "Creator",
        "XPAuthor",
        "LastModifiedBy",
        "ImageCreatorName",
    ],
    "location": [
        "GPSAltitude",
        "GPSAltitudeRef",
        "GPSLatitude",
        "GPSLatitudeRef",
        "GPSLongitude",
        "GPSLongitudeRef",
        "GPSPosition",
    ],
    "device": [
        "SerialNumber",
        "LensSerialNumber",
        "Model",
        "Make",
        "LensModel",
        "LensMake",
        "LensID",
        "Lens",
    ],
    "software": [
        "CreatorTool",
        "WriterName",
        "Software",
        "ReaderName",
        "OriginatingProgram",
        "Encoder",
        "Application",
        "EncodedBy",
        "ProcessingSoftware",
        "Producer",
    ],
}


class File:
    """
    File object, allows to easily extract metadata
    """

    def __init__(self, path: str):
        self._path = path
        self._all_metadata: Optional[Dict[str, Any]] = None
        self._mime_type: Optional[str] = None
        self._children: Optional[List[Self]] = None
        self._sha256: Optional[str] = None
        self.filename = os.path.basename(path)

    @property
    def children(self) -> List[Self]:
        """
        Access to children of the file
        If they weren't parsed before, parsed here
        """
        if self._children is None:
            self.get_children_files()
        if self._children is None:
            return []
        return self._children

    @property
    def mime_type(self) -> str:
        """
        Access mime type of the file
        """
        if self._mime_type is None:
            self.get_metadata()
        if self._mime_type is None:
            return ""
        return self._mime_type

    @property
    def path(self) -> str:
        """
        Access file path
        """
        return self._path

    def get_sha256(self):
        """
        Extract SHA256 hash of the file
        """
        with open(self.path, "rb") as f:
            sha256 = hashlib.sha256()
            sha256.update(f.read())
            self._sha256 = sha256.hexdigest()

    @property
    def sha256(self) -> str:
        """
        Return the SHA256 hash of the file
        """
        if self._sha256 is None:
            self.get_sha256()

        if self._sha256 is None:
            return ""

        return self._sha256

    def exists(self) -> bool:
        """
        Check if file exists
        """
        return os.path.isfile(self.path)

    def get_metadata(self) -> None:
        """
        Get metadata
        """
        try:
            out = subprocess.run(
                [self._get_exiftool_path(), "-json", self.path],
                check=True,
                stdout=subprocess.PIPE,
            ).stdout
        except subprocess.CalledProcessError:
            # FIXME: improve error handling?
            print("Exiftool can't parse {}".format(self.path))
            self._all_metadata = {}
        else:
            self._all_metadata = json.loads(out.decode("utf-8"))[0]
            self._mime_type = self.all_metadata["MIMEType"]
            for key in EXIFTOOL_META_ALLOWLIST:
                self._all_metadata.pop(key, None)

    @property
    def all_metadata(self) -> Dict[str, Any]:
        """
        Get all metadata from the file
        """
        if self._all_metadata is None:
            self.get_metadata()

        if self._all_metadata is None:
            return {}

        return self._all_metadata

    @property
    def metadata(self) -> Dict[str, Any]:
        """
        Get metadata from the file removing the useless entries from the allowlist
        """
        if self._all_metadata is None:
            self.get_metadata()

        if self._all_metadata is None:
            return {}

        m = self._all_metadata
        if META_ALLOWLIST:
            for key in META_ALLOWLIST:
                m.pop(key, None)
        return m

    @property
    def sensitive_metadata(self) -> Dict[str, Any]:
        """
        Get only sensitive metadata from the file
        """
        if self._all_metadata is None:
            self.get_metadata()

        meta: Dict[str, Any] = {}
        if self._all_metadata is not None and META_SENSITIVE is not None:
            for key in META_SENSITIVE:
                if key in self._all_metadata:
                    meta[key] = self._all_metadata[key]

        return meta

    def get_children_files(self) -> None:
        """
        Get files in the file
        For now, supports : pdf, docx, xlsx, pptx
        """
        self._children = []
        if self.mime_type == "application/pdf":
            try:
                from pypdf import PdfReader
            except ModuleNotFoundError:
                print("Impossible to find pypdf, please install it")
                sys.exit(1)

            logging.getLogger("pypdf").setLevel(logging.CRITICAL)
            reader = PdfReader(self.path)
            try:
                for page in reader.pages:
                    for img in page.images:
                        _, temp_file_path = tempfile.mkstemp()
                        with open(temp_file_path, "wb+") as f:
                            f.write(img.data)
                        # Create a new file
                        nf = File(temp_file_path)
                        nf.get_metadata()
                        nf.get_sha256()
                        nf.filename = img.name
                        self._children.append(nf)  # type: ignore
                        os.remove(temp_file_path)
            # Sometimes pypdf fails
            except:  # noqa: E722
                pass
        elif self.mime_type in [
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        ]:
            with zipfile.ZipFile(self.path) as fin:
                for child in fin.namelist():
                    if (
                        not child.startswith("word/media")
                        and not child.startswith("xl/media")
                        and not child.startswith("ppt/media/")
                    ):
                        continue
                    _, temp_file_path = tempfile.mkstemp()
                    with fin.open(child, "r") as f:
                        with open(temp_file_path, "wb+") as fout:
                            fout.write(f.read())

                    nf = File(temp_file_path)
                    nf.get_metadata()
                    nf.get_sha256()
                    nf.filename = child
                    self._children.append(nf)  # type: ignore
                    os.remove(temp_file_path)

    def get_summary(
        self, content: str = "useful", children: bool = False
    ) -> Dict[str, Any]:
        """
        Generate a summary of the metadata in this file

        :param content: level of metadata needed (all, useful, sensitive)
        :param children: extract data from children or not
        :return: dictionary
        """
        fdata: Dict[str, Any] = {
            "path": self._path,
            "name": self.filename,
            "sha256": self.sha256,
            "mime_type": self.mime_type,
        }
        if content == "all":
            fdata["metadata"] = self.all_metadata
        elif content == "sensitive":
            fdata["metadata"] = self.sensitive_metadata
        else:
            fdata["metadata"] = self.metadata

        if children:
            fdata["children"] = []
            for child in self.children:
                cdata: Dict[str, Any] = {
                    "path": self.path,
                    "name": child.filename,
                    "sha256": child.sha256,
                    "mime_type": child.mime_type,
                }
                if content == "all":
                    cdata["metadata"] = child.all_metadata
                elif content == "sensitive":
                    cdata["metadata"] = child.sensitive_metadata
                else:
                    cdata["metadata"] = child.metadata
                fdata["children"].append(cdata)

        return fdata

    @functools.lru_cache()
    def _get_exiftool_path(self) -> str:  # pragma: no cover
        """
        From MAT2
        https://github.com/tpet/mat2/blob/master/libmat2/exiftool.py
        """
        possible_pathes = {
            "/usr/bin/exiftool",  # debian/fedora
            "/usr/bin/vendor_perl/exiftool",  # archlinux
        }

        for possible_path in possible_pathes:
            if os.path.isfile(possible_path):
                if os.access(possible_path, os.X_OK):
                    return possible_path

        raise RuntimeError("Unable to find exiftool")


if __name__ == "__main__":
    # Parser
    parser = argparse.ArgumentParser(
        description="Process some files to extract metadata"
    )
    parser.add_argument("PATH", help="Folder or file path")
    parser.add_argument(
        "--output", "-o", help="Store data in output file", action="append"
    )
    parser.add_argument(
        "--level",
        "-l",
        default="useful",
        choices=["all", "useful", "sensitive"],
        help="How much metadata do you want?",
    )
    parser.add_argument(
        "--display",
        "-d",
        default="useful",
        choices=["all", "useful", "file", "none"],
        help="What do you want displayed?",
    )
    parser.add_argument(
        "--children",
        "-c",
        action="store_true",
        help="Tries to parse metadata of files within files",
    )
    parser.add_argument(
        "--summary",
        "-s",
        help="Generate and dumps a summary of the data in a given file",
    )
    args = parser.parse_args()

    # Load metadata lists
    script_dir = os.path.dirname(os.path.realpath(__file__))
    with open(
        os.path.join(script_dir, "metadata_allowlist.txt"), "r", encoding="utf-8"
    ) as f:
        META_ALLOWLIST = {line.strip() for line in f.read().split()}
    with open(
        os.path.join(script_dir, "metadata_sensitivelist.txt"), "r", encoding="utf-8"
    ) as f:
        META_SENSITIVE = {line.strip() for line in f.read().split()}

    # Parse the files
    output_data = []
    if os.path.isfile(args.PATH):
        file = File(args.PATH)
        fdata = file.get_summary(args.level, args.children)
        print(json.dumps(fdata, indent=4))
        output_data.append(fdata)
    elif os.path.isdir(args.PATH):
        for root, dirs, files in os.walk(args.PATH):
            for file in files:
                fpath = os.path.join(root, file)
                file = File(fpath)
                fdata = file.get_summary(args.level, args.children)
                if args.display == "file":
                    print(fpath)
                elif args.display == "useful":
                    if len(fdata["metadata"]) > 0:
                        print(
                            "{} : {}".format(
                                fpath, json.dumps(fdata["metadata"], indent=4)
                            )
                        )
                elif args.display == "all":
                    print(
                        "{} : {}".format(fpath, json.dumps(fdata["metadata"], indent=4))
                    )

                for child in fdata.get("children", []):
                    if args.display == "file":
                        print(f"{fpath} / {child['name']}")
                    elif args.display == "all":
                        print(
                            "{} / {} : {}".format(
                                fpath,
                                child["name"],
                                json.dumps(child["metadata"], indent=4),
                            )
                        )
                    elif args.display == "useful":
                        if len(child["metadata"]) > 0:
                            print(
                                "{} / {} : {}".format(
                                    fpath,
                                    child["name"],
                                    json.dumps(child["metadata"], indent=4),
                                )
                            )

                output_data.append(fdata)
    else:
        print("Invalid path, quitting")

    # Make a summary of the data
    if args.summary is not None:
        summary: Dict[str, Any] = {}
        for data_type, keys in META_STRUCTURE.items():
            summary[data_type] = {}
            # For each metadata name
            for mname in keys:
                # Got through files and search for it
                for entry in output_data:
                    if mname in entry["metadata"]:
                        if entry["metadata"][mname] in summary[data_type]:
                            if (
                                entry["path"]
                                not in summary[data_type][entry["metadata"][mname]]
                            ):
                                summary[data_type][entry["metadata"][mname]].append(
                                    entry["path"]
                                )
                        else:
                            summary[data_type][entry["metadata"][mname]] = [
                                entry["path"]
                            ]
                    for child in entry.get("children", []):
                        if mname in child["metadata"]:
                            fname = f"{entry['path']} {child['name']}"
                            if child["metadata"][mname] in summary[data_type]:
                                if (
                                    fname
                                    not in summary[data_type][child["metadata"][mname]]
                                ):
                                    summary[data_type][child["metadata"][mname]].append(
                                        fname
                                    )
                            else:
                                summary[data_type][child["metadata"][mname]] = [fname]

        print(json.dumps(summary, indent=4))
        with open(args.summary, "w+", encoding="utf-8") as f:
            f.write(json.dumps(summary, indent=4))

    # Write output if needed
    if args.output is not None and len(output_data) > 0:
        for output in args.output:
            if output.endswith(".json"):
                with open(output, "w+", encoding="utf-8") as f:
                    f.write(json.dumps(output_data, indent=4))

                print(f"Output written in {output}")

            elif output.endswith("csv"):
                # Get full list of unique keys
                output_keys = []
                for entry in output_data:
                    for k in entry["metadata"]:
                        output_keys.append(k)
                    if "children" in entry:
                        for child in entry["children"]:
                            for k in child["metadata"]:
                                output_keys.append(k)
                output_keys = sorted(list(set(output_keys)))

                with open(output, "w+", encoding="utf-8") as csvfile:
                    writer = csv.writer(csvfile)
                    writer.writerow(["Path", "Name", "SHA256", "MIME"] + output_keys)
                    for entry in output_data:
                        if len(entry["metadata"]) == 0:
                            continue
                        line = [
                            entry["path"],
                            entry["name"],
                            entry["sha256"],
                            entry["mime_type"],
                        ]
                        for k in output_keys:
                            if k in entry["metadata"]:
                                line.append(entry["metadata"][k])
                            else:
                                line.append("")
                        writer.writerow(line)

                        # Then children
                        for child in entry.get("children", []):
                            if len(child["metadata"]) == 0:
                                continue

                            line = [
                                entry["path"],
                                entry["name"] + " / " + child["name"],
                                child["sha256"],
                                child["mime_type"],
                            ]
                            for k in output_keys:
                                if k in child["metadata"]:
                                    line.append(child["metadata"][k])
                                else:
                                    line.append("")
                            writer.writerow(line)
                print(f"Output written in {output}")
            else:
                print(f"Output format unknown for {output}, skipping")
