# Third-party notices

Disk Rescue combines an original PowerShell/C# wrapper with separately executed third-party programs. The repository's MIT license covers only the original wrapper, installer, build scripts and documentation. It **does not relicense** any embedded executable, DLL, upstream source archive, upstream documentation or upstream notice.

The release's `Recover-Disk.ps1` embeds an engine ZIP as data. The same engine archive is kept in `assets/engines.zip`. Starting an image session extracts these files into `engines/tsk` and `engines/photorec`. Original notices and source archives travel with the payload.

## The Sleuth Kit 4.15.0

- Project: [The Sleuth Kit](https://www.sleuthkit.org/sleuthkit/).
- Upstream release: [sleuthkit-4.15.0](https://github.com/sleuthkit/sleuthkit/releases/tag/sleuthkit-4.15.0).
- Original Windows distribution: [sleuthkit-4.15.0-win32.zip](https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.15.0/sleuthkit-4.15.0-win32.zip).
- Corresponding TSK source: [sleuthkit-4.15.0.tar.gz](https://github.com/sleuthkit/sleuthkit/releases/download/sleuthkit-4.15.0/sleuthkit-4.15.0.tar.gz), included in the payload at `tsk/source/sleuthkit-4.15.0.tar.gz`.

This wrapper uses `mmls.exe`, `fsstat.exe`, `fls.exe` and `icat.exe`. TSK filesystem tools are distributed under the **IBM Public License 1.0** and **Common Public License 1.0**, as described by upstream. TSK also contains components with their own notices, including MIT/BSD-licensed utilities. The complete upstream source archive contains its `licenses/README.md`, license texts and source-level notices.

Retained primary copyright notices include:

```text
Copyright (c) 1997,1998,1999, International Business Machines
Corporation and others. All Rights Reserved.

Copyright (c) 2002-2003 Brian Carrier, @stake Inc. All rights reserved
Copyright (c) 2003-2005 Brian Carrier. All rights reserved
Copyright (c) 2006-2011 Brian Carrier, Basis Technology. All Rights reserved
```

Copies of the [IBM Public License](docs/licenses/TSK-IBM-LICENSE) and [Common Public License](docs/licenses/TSK-CPL-1.0.txt) are included in this repository; the payload retains `tsk/licenses/`, `README.txt` and `README-win32.txt`.

### Local resource modification

Disk Rescue contributors changed the embedded Windows application manifest of the four listed EXE files to add `activeCodePage=UTF-8`. This enables Unicode names on supported Windows versions. The change targets the manifest resource; executable code was not intentionally changed. The modified resources are supplied under the same terms as the respective TSK program.

The payload retains `tsk/patch_utf8_manifest.py`, `tsk/utf8-manifest-patches.json`, `tsk/PROVENANCE.txt` and `tsk/engine-manifest.json`. Original and patched EXE SHA-256 values are recorded in these files and release build metadata. Unmodified DLLs were copied from the official Windows archive.

Official archive SHA-256:

```text
Windows ZIP  c2ebab8105b893d97bd8ce35b88e01985e2a106efc97f03adf95840a631b20ce
TSK source   3a8c1e7d18a9b81f3e5e8aa78313974aceaafc6e051d636bc92cd7168286eca9
```

The payload also retains DLLs provided by that Windows distribution: TSK's image/JNI helpers, `libewf.dll`, `libvhdi.dll`, `libvmdk.dll`, OpenSSL 1.1 libraries, zlib, Microsoft Visual C++ runtime libraries and Universal CRT libraries. These are separate third-party components with their own upstream terms; the wrapper's MIT license does not apply to them. Their presence in the payload does not expose every image format through the Disk Rescue interface.

Upstream projects and distribution information:

- [libewf](https://github.com/libyal/libewf), [libvhdi](https://github.com/libyal/libvhdi), [libvmdk](https://github.com/libyal/libvmdk).
- [OpenSSL](https://www.openssl.org/) and its [1.1.1 source and notices](https://github.com/openssl/openssl/tree/OpenSSL_1_1_1-stable).
- [zlib](https://www.zlib.net/).
- [Microsoft Visual C++ runtime distribution information](https://learn.microsoft.com/en-us/cpp/windows/redistributing-visual-cpp-files).

## PhotoRec 7.2

- Author and maintainer: Christophe GRENIER and contributors; original authorship notices are retained in `AUTHORS.txt` and source files.
- Project and documentation: [CGSecurity PhotoRec](https://www.cgsecurity.org/wiki/PhotoRec).
- Original Windows distribution: [testdisk-7.2.win64.zip](https://www.cgsecurity.org/testdisk-7.2.win64.zip).
- Corresponding TestDisk/PhotoRec source: [testdisk-7.2.tar.bz2](https://www.cgsecurity.org/testdisk-7.2.tar.bz2), included in the payload at `photorec/source/testdisk-7.2.tar.bz2`.

PhotoRec is free software under the **GNU General Public License version 2 or, at your option, any later version**, as stated in its source. A copy of [GPL version 2](docs/licenses/PHOTOREC-GPL-2.0.txt) is included here and in the payload's `photorec/COPYING.txt`.

Disk Rescue bundles the terminal program `photorec_win.exe` and its required runtime files from the official archive. It does not modify PhotoRec. The TestDisk partition-editing program and QPhotoRec GUI are not used by this wrapper.

The included runtime files are `cygwin1.dll`, `cygewf-2.dll`, `cyggcc_s-seh-1.dll`, `cygiconv-2.dll`, `cygjpeg-8.dll`, `cygncursesw-10.dll` and `cygz.dll`, together with upstream runtime support files. They remain subject to their respective upstream licenses and exceptions, rather than the wrapper's MIT license. Relevant upstream projects and source-distribution information:

- [Cygwin licensing and source distribution](https://cygwin.com/licensing.html).
- [libewf](https://github.com/libyal/libewf).
- [GCC runtime library exception](https://gcc.gnu.org/onlinedocs/libstdc++/manual/license.html).
- [GNU libiconv](https://www.gnu.org/software/libiconv/).
- [Independent JPEG Group](https://www.ijg.org/).
- [ncurses](https://invisible-island.net/ncurses/).
- [zlib](https://www.zlib.net/).

The included TSK and TestDisk source archives are the corresponding upstream **project** sources. They should not be interpreted as a claim that those archives contain the complete source of every separately supplied runtime DLL.

## Disclaimers and redistribution

All upstream copyright and license notices remain applicable. The upstream components are supplied as-is, without warranties or promises that damaged, overwritten or trimmed data can be recovered. Applicable warranty and liability exclusions are set out in their license texts. No additional warranty is offered on behalf of upstream contributors.

Anyone redistributing a modified or repackaged release should retain the original notices, source archives and modification description, and review the license terms of every included component. The software names DMDE, Microsoft Windows, The Sleuth Kit and PhotoRec identify independent products; they do not imply endorsement or affiliation.
