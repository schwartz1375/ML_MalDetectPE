#!/usr/bin/env python3
import pefile
import os
import hashlib
import array
import math

def get_md5(fname):
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurences = array.array('L', [0] * 256)
    for x in data:
        occurences[x if isinstance(x, int) else ord(x)] += 1
    entropy = 0
    for x in occurences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

    return entropy

def get_resources(pe):
    """Extract resources :
    [entropy, size]"""
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(
                                    resource_lang.data.struct.OffsetToData,
                                    resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources


def get_version_info(pe):
    """Return version infos"""
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
        res['os'] = pe.VS_FIXEDFILEINFO.FileOS
        res['type'] = pe.VS_FIXEDFILEINFO.FileType
        res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
        res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
        res['signature'] = pe.VS_FIXEDFILEINFO.Signature
        res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res


def extract_infos(fpath):
    res = []
    res.append(os.path.basename(fpath))
    res.append(get_md5(fpath))
    pe = pefile.PE(fpath)
    #res.append(pe.get_imphash())
    res.append(pe.FILE_HEADER.Machine)
    res.append(pe.FILE_HEADER.SizeOfOptionalHeader)
    res.append(pe.FILE_HEADER.Characteristics)
    res.append(pe.OPTIONAL_HEADER.MajorLinkerVersion)
    res.append(pe.OPTIONAL_HEADER.MinorLinkerVersion)
    res.append(pe.OPTIONAL_HEADER.SizeOfCode)
    res.append(pe.OPTIONAL_HEADER.SizeOfInitializedData)
    res.append(pe.OPTIONAL_HEADER.SizeOfUninitializedData)
    res.append(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
    res.append(pe.OPTIONAL_HEADER.BaseOfCode)
    try:
        res.append(pe.OPTIONAL_HEADER.BaseOfData)
    except AttributeError:
        res.append(0)
    res.append(pe.OPTIONAL_HEADER.ImageBase)
    res.append(pe.OPTIONAL_HEADER.SectionAlignment)
    res.append(pe.OPTIONAL_HEADER.FileAlignment)
    res.append(pe.OPTIONAL_HEADER.MajorOperatingSystemVersion)
    res.append(pe.OPTIONAL_HEADER.MinorOperatingSystemVersion)
    res.append(pe.OPTIONAL_HEADER.MajorImageVersion)
    res.append(pe.OPTIONAL_HEADER.MinorImageVersion)
    res.append(pe.OPTIONAL_HEADER.MajorSubsystemVersion)
    res.append(pe.OPTIONAL_HEADER.MinorSubsystemVersion)
    res.append(pe.OPTIONAL_HEADER.SizeOfImage)
    res.append(pe.OPTIONAL_HEADER.SizeOfHeaders)
    res.append(pe.OPTIONAL_HEADER.CheckSum)
    res.append(pe.OPTIONAL_HEADER.Subsystem)
    res.append(pe.OPTIONAL_HEADER.DllCharacteristics)
    res.append(pe.OPTIONAL_HEADER.SizeOfStackReserve)
    res.append(pe.OPTIONAL_HEADER.SizeOfStackCommit)
    res.append(pe.OPTIONAL_HEADER.SizeOfHeapReserve)
    res.append(pe.OPTIONAL_HEADER.SizeOfHeapCommit)
    res.append(pe.OPTIONAL_HEADER.LoaderFlags)
    res.append(pe.OPTIONAL_HEADER.NumberOfRvaAndSizes)
    res.append(len(pe.sections))
    entropy = list(map(lambda x:x.get_entropy(), pe.sections))
    if len(entropy) > 0:
        res.append(sum(entropy) / float(len(entropy)))
        res.append(min(entropy))
        res.append(max(entropy))
    else:
        res.append(0)
        res.append(0)
        res.append(0)
    # Get the sizes of the raw data for each section
    raw_sizes = list(map(lambda x: x.SizeOfRawData, pe.sections))
    if len(raw_sizes) > 0:
        # Compute some statistics on the raw data sizes
        res.append(sum(raw_sizes) / float(len(raw_sizes)))
        res.append(min(raw_sizes))
        res.append(max(raw_sizes))
    else:
        res.append(0)
        res.append(0)
        res.append(0)

    # Get the virtual sizes for each section
    virtual_sizes = list(map(lambda x: x.Misc_VirtualSize, pe.sections))
    if len(virtual_sizes) > 0:
        # Compute some statistics on the virtual sizes
        res.append(sum(virtual_sizes) / float(len(virtual_sizes)))
        res.append(min(virtual_sizes))
        res.append(max(virtual_sizes))
    else:
        res.append(0)
        res.append(0)
        res.append(0)
    #Imports
    try:
        res.append(len(pe.DIRECTORY_ENTRY_IMPORT))
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        res.append(len(imports))
        res.append(len(list(filter(lambda x: x.name is None, imports))))
    except AttributeError:
        res.append(0)
        res.append(0)
        res.append(0)
    #Exports
    try:
        res.append(len(pe.DIRECTORY_ENTRY_EXPORT.symbols))
    except AttributeError:
        # No export
        res.append(0)
    #Resources
    resources = get_resources(pe)
    res.append(len(resources))
    if len(resources) > 0:
        entropy = list(map(lambda x: x[0], resources))
        res.append(sum(entropy) / float(len(entropy)))
        res.append(min(entropy))
        res.append(max(entropy))
        sizes = list(map(lambda x: x[1], resources))
        res.append(sum(sizes) / float(len(sizes)))
        res.append(min(sizes))
        res.append(max(sizes))
    else:
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)
        res.append(0)

    # Load configuration size
    try:
        res.append(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size)
    except AttributeError:
        res.append(0)
    # Version configuration size
    try:
        version_infos = get_version_info(pe)
        res.append(len(version_infos.keys()))
    except AttributeError:
        res.append(0)
    return res

if __name__ == '__main__':
    csv_delimiter = "|"
    columns = [
        "Name", "md5", "impash", "Machine", "SizeOfOptionalHeader", "Characteristics",
        "MajorLinkerVersion", "MinorLinkerVersion", "SizeOfCode",
        "SizeOfInitializedData", "SizeOfUninitializedData",
        "AddressOfEntryPoint", "BaseOfCode", "BaseOfData", "ImageBase",
        "SectionAlignment", "FileAlignment", "MajorOperatingSystemVersion",
        "MinorOperatingSystemVersion", "MajorImageVersion",
        "MinorImageVersion", "MajorSubsystemVersion", "MinorSubsystemVersion",
        "SizeOfImage", "SizeOfHeaders", "CheckSum", "Subsystem",
        "DllCharacteristics", "SizeOfStackReserve", "SizeOfStackCommit",
        "SizeOfHeapReserve", "SizeOfHeapCommit", "LoaderFlags",
        "NumberOfRvaAndSizes", "SectionsNb", "SectionsMeanEntropy",
        "SectionsMinEntropy", "SectionsMaxEntropy", "SectionsMeanRawsize",
        "SectionsMinRawsize", "SectionMaxRawsize", "SectionsMeanVirtualsize",
        "SectionsMinVirtualsize", "SectionMaxVirtualsize", "ImportsNbDLL",
        "ImportsNb", "ImportsNbOrdinal", "ExportNb", "ResourcesNb",
        "ResourcesMeanEntropy", "ResourcesMinEntropy", "ResourcesMaxEntropy",
        "ResourcesMeanSize", "ResourcesMinSize", "ResourcesMaxSize",
        "LoadConfigurationSize", "VersionInformationSize", "legitimate"
    ]

    # Launch legitimate
    # Open the file for writing
    outFile = "output_test.csv"
    with open(outFile, 'a') as ff:
        # Write the header row to the file
        ff.write(csv_delimiter.join(columns) + "\n")

        # Loop over all files in the 'legitimate' directory
        for ffile in os.listdir('legitimate'):
            print(ffile)

            # Attempt to extract information from the PE file
            try:
                # Call the extract_infos() function to get information about the file
                res = extract_infos(os.path.join('legitimate/', ffile))

                # Append a label indicating that the file is legitimate (1)
                res.append(1)

                # Convert the list of extracted information to a CSV row and write it to the file
                ff.write(csv_delimiter.join(map(str, res)) + "\n")

            # Handle the case where the PE file is not well-formed
            except pefile.PEFormatError:
                print('\t -> Bad PE format')

    # Open the file for writing
    with open(outFile, 'a') as ff:
        # Loop over all files in the 'legitimate' directory
        for ffile in os.listdir('malicious'):
            print(ffile)

            # Attempt to extract information from the PE file
            try:
                # Call the extract_infos() function to get information about the file
                res = extract_infos(os.path.join('malicious/', ffile))

                # Append a label indicating that the file is legitimate (1)
                res.append(0)

                # Convert the list of extracted information to a CSV row and write it to the file
                ff.write(csv_delimiter.join(map(str, res)) + "\n")

            # Handle the case where the PE file is not well-formed
            except pefile.PEFormatError:
                print('\t -> Bad PE format')
