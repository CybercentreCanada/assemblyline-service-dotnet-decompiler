"""This Assemblyline service decompiles .NET dlls."""

import os
import shutil
import subprocess

from assemblyline_v4_service.common.base import ServiceBase
from assemblyline_v4_service.common.request import ServiceRequest
from assemblyline_v4_service.common.result import Result, ResultKeyValueSection


class DotnetDecompiler(ServiceBase):
    """This Assemblyline service decompiles .NET dlls."""

    def execute(self, request: ServiceRequest):
        request.result = Result()

        # Start by decompiling everything as one file for further analysis
        popenargs = ["ilspycmd", "--disable-updatecheck", "--outputdir", self.working_directory, request.file_path]
        p = subprocess.run(popenargs, capture_output=True)

        if p.returncode != 0:
            errors = p.stderr
            if "System.BadImageFormatException" in p.stderr:
                # Not a Dotnet File
                return
            if "PEFileNotSupportedException" in errors:
                # File not supported by ILSpy, probably not a Dotnet File
                return
            if "System.NullReferenceException: Object reference not set to an instance of an object" in errors:
                # A real Dotnet File, but corrupted
                return
            # Unexpected error
            raise Exception(errors)

        # ILSpy always extracts following the input filename
        decompiled_file_path = os.path.join(
            self.working_directory, os.path.splitext(os.path.basename(request.file_path))[0] + ".decompiled.cs"
        )
        if not os.path.exists(decompiled_file_path):
            raise Exception("No ILSpy decompilation found.")

        assembly_info = ResultKeyValueSection("Assembly Information")

        with open(decompiled_file_path, "r") as decompiled_file:
            for line in decompiled_file:
                if line.startswith("[assembly: "):
                    k, v = line[11:].split("(", 1)
                    v = v[::-1].split(")", 1)[-1][::-1]
                    assembly_info.set_item(k, v)

        if assembly_info.body:
            request.result.add_section(assembly_info)

        request.add_extracted(
            name=os.path.basename(decompiled_file_path), description="Decompiled file", path=decompiled_file_path
        )

        # In case decompilation is too mangled, the IL Code could give more hints as to what the executable is doing.
        popenargs = [
            "ilspycmd",
            "--disable-updatecheck",
            "--ilcode",
            # "--il-sequence-points", # Show IL with sequence points.
            "--outputdir",
            self.working_directory,
            request.file_path,
        ]
        p = subprocess.run(popenargs, capture_output=True)
        if p.returncode == 0:
            il_file_path = os.path.join(
                self.working_directory, os.path.splitext(os.path.basename(request.file_path))[0] + ".il"
            )
            request.add_supplementary(
                name=os.path.basename(il_file_path), description="IL Code file", path=il_file_path
            )

        # For easier download, browsing, and compilation, split the project in multiple files
        project_folder = os.path.join(self.working_directory, "project")
        popenargs = [
            "ilspycmd",
            "--disable-updatecheck",
            "--project",
            "--nested-directories",
            "--outputdir",
            project_folder,
            request.file_path,
        ]
        p = subprocess.run(popenargs, capture_output=True)
        if p.returncode != 0:
            return

        for root, _, files in os.walk(project_folder):
            for f in files:
                file_path = os.path.join(root, f)
                request.add_supplementary(name=os.path.basename(file_path), description="Project file", path=file_path)
        shutil.make_archive(os.path.join(self.working_directory, "project"), "zip", project_folder)
        request.add_supplementary(
            name="project.zip", description="Project folder", path=os.path.join(self.working_directory, "project.zip")
        )

        # There is also the --generate-pdb option that could yield interesting information.
